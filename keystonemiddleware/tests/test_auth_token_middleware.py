# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import calendar
import datetime
import json
import logging
import os
import shutil
import stat
import tempfile
import time
import uuid

import fixtures
from keystoneclient import access
from keystoneclient import auth
from keystoneclient.common import cms
from keystoneclient import exceptions
from keystoneclient import fixture
from keystoneclient import session
import mock
from oslo_config import fixture as cfg_fixture
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from requests_mock.contrib import fixture as rm_fixture
import six
import testresources
import testtools
from testtools import matchers
import webob
import webob.dec

from keystonemiddleware import auth_token
from keystonemiddleware.openstack.common import memorycache
from keystonemiddleware.tests import client_fixtures
from keystonemiddleware.tests import utils


EXPECTED_V2_DEFAULT_ENV_RESPONSE = {
    'HTTP_X_IDENTITY_STATUS': 'Confirmed',
    'HTTP_X_TENANT_ID': 'tenant_id1',
    'HTTP_X_TENANT_NAME': 'tenant_name1',
    'HTTP_X_USER_ID': 'user_id1',
    'HTTP_X_USER_NAME': 'user_name1',
    'HTTP_X_ROLES': 'role1,role2',
    'HTTP_X_USER': 'user_name1',  # deprecated (diablo-compat)
    'HTTP_X_TENANT': 'tenant_name1',  # deprecated (diablo-compat)
    'HTTP_X_ROLE': 'role1,role2',  # deprecated (diablo-compat)
}

EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE = {
    'HTTP_X_SERVICE_PROJECT_ID': 'service_project_id1',
    'HTTP_X_SERVICE_PROJECT_NAME': 'service_project_name1',
    'HTTP_X_SERVICE_USER_ID': 'service_user_id1',
    'HTTP_X_SERVICE_USER_NAME': 'service_user_name1',
    'HTTP_X_SERVICE_ROLES': 'service_role1,service_role2',
}

EXPECTED_V3_DEFAULT_ENV_ADDITIONS = {
    'HTTP_X_PROJECT_DOMAIN_ID': 'domain_id1',
    'HTTP_X_PROJECT_DOMAIN_NAME': 'domain_name1',
    'HTTP_X_USER_DOMAIN_ID': 'domain_id1',
    'HTTP_X_USER_DOMAIN_NAME': 'domain_name1',
}

EXPECTED_V3_DEFAULT_SERVICE_ENV_ADDITIONS = {
    'HTTP_X_SERVICE_PROJECT_DOMAIN_ID': 'service_domain_id1',
    'HTTP_X_SERVICE_PROJECT_DOMAIN_NAME': 'service_domain_name1',
    'HTTP_X_SERVICE_USER_DOMAIN_ID': 'service_domain_id1',
    'HTTP_X_SERVICE_USER_DOMAIN_NAME': 'service_domain_name1'
}


BASE_HOST = 'https://keystone.example.com:1234'
BASE_URI = '%s/testadmin' % BASE_HOST
FAKE_ADMIN_TOKEN_ID = 'admin_token2'
FAKE_ADMIN_TOKEN = jsonutils.dumps(
    {'access': {'token': {'id': FAKE_ADMIN_TOKEN_ID,
                          'expires': '2022-10-03T16:58:01Z'}}})

VERSION_LIST_v3 = fixture.DiscoveryList(href=BASE_URI)
VERSION_LIST_v2 = fixture.DiscoveryList(v3=False, href=BASE_URI)

ERROR_TOKEN = '7ae290c2a06244c4b41692eb4e9225f2'
MEMCACHED_SERVERS = ['localhost:11211']
MEMCACHED_AVAILABLE = None


def memcached_available():
    """Do a sanity check against memcached.

    Returns ``True`` if the following conditions are met (otherwise, returns
    ``False``):

    - ``python-memcached`` is installed
    - a usable ``memcached`` instance is available via ``MEMCACHED_SERVERS``
    - the client is able to set and get a key/value pair

    """
    global MEMCACHED_AVAILABLE

    if MEMCACHED_AVAILABLE is None:
        try:
            import memcache
            c = memcache.Client(MEMCACHED_SERVERS)
            c.set('ping', 'pong', time=1)
            MEMCACHED_AVAILABLE = c.get('ping') == 'pong'
        except ImportError:
            MEMCACHED_AVAILABLE = False

    return MEMCACHED_AVAILABLE


def cleanup_revoked_file(filename):
    try:
        os.remove(filename)
    except OSError:
        pass


class TimezoneFixture(fixtures.Fixture):
    @staticmethod
    def supported():
        # tzset is only supported on Unix.
        return hasattr(time, 'tzset')

    def __init__(self, new_tz):
        super(TimezoneFixture, self).__init__()
        self.tz = new_tz
        self.old_tz = os.environ.get('TZ')

    def setUp(self):
        super(TimezoneFixture, self).setUp()
        if not self.supported():
            raise NotImplementedError('timezone override is not supported.')
        os.environ['TZ'] = self.tz
        time.tzset()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.old_tz is not None:
            os.environ['TZ'] = self.old_tz
        elif 'TZ' in os.environ:
            del os.environ['TZ']
        time.tzset()


class TimeFixture(fixtures.Fixture):

    def __init__(self, new_time, normalize=True):
        super(TimeFixture, self).__init__()
        if isinstance(new_time, six.string_types):
            new_time = timeutils.parse_isotime(new_time)
        if normalize:
            new_time = timeutils.normalize_time(new_time)
        self.new_time = new_time

    def setUp(self):
        super(TimeFixture, self).setUp()
        timeutils.set_time_override(self.new_time)
        self.addCleanup(timeutils.clear_time_override)


class FakeApp(object):
    """This represents a WSGI app protected by the auth_token middleware."""

    SUCCESS = b'SUCCESS'
    FORBIDDEN = b'FORBIDDEN'
    expected_env = {}

    def __init__(self, expected_env=None, need_service_token=False):
        self.expected_env = dict(EXPECTED_V2_DEFAULT_ENV_RESPONSE)

        if expected_env:
            self.expected_env.update(expected_env)

        self.need_service_token = need_service_token

    def __call__(self, env, start_response):
        for k, v in self.expected_env.items():
            assert env[k] == v, '%s != %s' % (env[k], v)

        resp = webob.Response()

        if env['HTTP_X_IDENTITY_STATUS'] == 'Invalid':
            # Simulate delayed auth forbidding access
            resp.status = 403
            resp.body = FakeApp.FORBIDDEN
        elif (self.need_service_token is True and
                env.get('HTTP_X_SERVICE_TOKEN') is None):
            # Simulate requiring composite auth
            # Arbitrary value to allow checking this code path
            resp.status = 418
            resp.body = FakeApp.FORBIDDEN
        else:
            resp.body = FakeApp.SUCCESS

        return resp(env, start_response)


class v3FakeApp(FakeApp):
    """This represents a v3 WSGI app protected by the auth_token middleware."""

    def __init__(self, expected_env=None, need_service_token=False):

        # with v3 additions, these are for the DEFAULT TOKEN
        v3_default_env_additions = dict(EXPECTED_V3_DEFAULT_ENV_ADDITIONS)
        if expected_env:
            v3_default_env_additions.update(expected_env)
        super(v3FakeApp, self).__init__(expected_env=v3_default_env_additions,
                                        need_service_token=need_service_token)


class CompositeBase(object):
    """Base composite auth object with common service token environment."""

    def __init__(self, expected_env=None):
        comp_expected_env = dict(EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE)

        if expected_env:
            comp_expected_env.update(expected_env)

        super(CompositeBase, self).__init__(
            expected_env=comp_expected_env, need_service_token=True)


class CompositeFakeApp(CompositeBase, FakeApp):
    """A fake v2 WSGI app protected by composite auth_token middleware."""

    def __init__(self, expected_env):
        super(CompositeFakeApp, self).__init__(expected_env=expected_env)


class v3CompositeFakeApp(CompositeBase, v3FakeApp):
    """A fake v3 WSGI app protected by composite auth_token middleware."""

    def __init__(self, expected_env=None):

        # with v3 additions, these are for the DEFAULT SERVICE TOKEN
        v3_default_service_env_additions = dict(
            EXPECTED_V3_DEFAULT_SERVICE_ENV_ADDITIONS)

        if expected_env:
            v3_default_service_env_additions.update(expected_env)

        super(v3CompositeFakeApp, self).__init__(
            v3_default_service_env_additions)


def new_app(status, body, headers={}):

    class _App(object):

        def __init__(self, expected_env=None):
            self.expected_env = expected_env

        @webob.dec.wsgify
        def __call__(self, req):
            resp = webob.Response(body, status)
            resp.headers.update(headers)
            return resp

    return _App


class BaseAuthTokenMiddlewareTest(testtools.TestCase):
    """Base test class for auth_token middleware.

    All the tests allow for running with auth_token
    configured for receiving v2 or v3 tokens, with the
    choice being made by passing configuration data into
    setUp().

    The base class will, by default, run all the tests
    expecting v2 token formats.  Child classes can override
    this to specify, for instance, v3 format.

    """
    def setUp(self, expected_env=None, auth_version=None, fake_app=None):
        super(BaseAuthTokenMiddlewareTest, self).setUp()

        self.expected_env = expected_env or dict()
        self.fake_app = fake_app or FakeApp
        self.middleware = None
        self.requests = self.useFixture(rm_fixture.Fixture())

        signing_dir = self._setup_signing_directory()

        self.conf = {
            'identity_uri': 'https://keystone.example.com:1234/testadmin/',
            'signing_dir': signing_dir,
            'auth_version': auth_version,
            'auth_uri': 'https://keystone.example.com:1234',
            'admin_user': uuid.uuid4().hex,
        }

        self.auth_version = auth_version
        self.response_status = None
        self.response_headers = None

    def _setup_signing_directory(self):
        directory_name = self.useFixture(fixtures.TempDir()).path

        # Copy the sample certificate files into the temporary directory.
        for filename in ['cacert.pem', 'signing_cert.pem', ]:
            shutil.copy2(os.path.join(client_fixtures.CERTDIR, filename),
                         os.path.join(directory_name, filename))

        return directory_name

    def set_middleware(self, expected_env=None, conf=None):
        """Configure the class ready to call the auth_token middleware.

        Set up the various fake items needed to run the middleware.
        Individual tests that need to further refine these can call this
        function to override the class defaults.

        """
        if conf:
            self.conf.update(conf)

        if expected_env:
            self.expected_env.update(expected_env)

        self.middleware = auth_token.AuthProtocol(
            self.fake_app(self.expected_env), self.conf)

        self.middleware._token_revocation_list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})

    def update_expected_env(self, expected_env={}):
        self.middleware._app.expected_env.update(expected_env)

    def purge_token_expected_env(self):
        for key in six.iterkeys(self.token_expected_env):
            del self.middleware._app.expected_env[key]

    def purge_service_token_expected_env(self):
        for key in six.iterkeys(self.service_token_expected_env):
            del self.middleware._app.expected_env[key]

    def start_fake_response(self, status, headers, exc_info=None):
        self.response_status = int(status.split(' ', 1)[0])
        self.response_headers = dict(headers)

    def assertLastPath(self, path):
        if path:
            self.assertEqual(BASE_URI + path, self.requests.last_request.url)
        else:
            self.assertIsNone(self.requests.last_request)


class DiabloAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                    testresources.ResourcedTestCase):

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    """Auth Token middleware should understand Diablo keystone responses."""
    def setUp(self):
        # pre-diablo only had Tenant ID, which was also the Name
        expected_env = {
            'HTTP_X_TENANT_ID': 'tenant_id1',
            'HTTP_X_TENANT_NAME': 'tenant_id1',
            # now deprecated (diablo-compat)
            'HTTP_X_TENANT': 'tenant_id1',
        }

        super(DiabloAuthTokenMiddlewareTest, self).setUp(
            expected_env=expected_env)

        self.requests.get(BASE_URI,
                          json=VERSION_LIST_v2,
                          status_code=300)

        self.requests.post("%s/v2.0/tokens" % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        self.token_id = self.examples.VALID_DIABLO_TOKEN
        token_response = self.examples.JSON_TOKEN_RESPONSES[self.token_id]

        url = "%s/v2.0/tokens/%s" % (BASE_URI, self.token_id)
        self.requests.get(url, text=token_response)

        self.set_middleware()

    def test_valid_diablo_response(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_id
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertIn('keystone.token_info', req.environ)


class NoMemcacheAuthToken(BaseAuthTokenMiddlewareTest):
    """These tests will not have the memcache module available."""

    def setUp(self):
        super(NoMemcacheAuthToken, self).setUp()
        self.useFixture(utils.DisableModuleFixture('memcache'))

    def test_nomemcache(self):
        conf = {
            'admin_token': 'admin_token1',
            'auth_host': 'keystone.example.com',
            'auth_port': '1234',
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'auth_uri': 'https://keystone.example.com:1234',
        }

        auth_token.AuthProtocol(FakeApp(), conf)


class CachePoolTest(BaseAuthTokenMiddlewareTest):
    def test_use_cache_from_env(self):
        """If `swift.cache` is set in the environment and `cache` is set in the
        config then the env cache is used.
        """
        env = {'swift.cache': 'CACHE_TEST'}
        conf = {
            'cache': 'swift.cache'
        }
        self.set_middleware(conf=conf)
        self.middleware._token_cache.initialize(env)
        with self.middleware._token_cache._cache_pool.reserve() as cache:
            self.assertEqual(cache, 'CACHE_TEST')

    def test_not_use_cache_from_env(self):
        """If `swift.cache` is set in the environment but `cache` isn't set in
        the config then the env cache isn't used.
        """
        self.set_middleware()
        env = {'swift.cache': 'CACHE_TEST'}
        self.middleware._token_cache.initialize(env)
        with self.middleware._token_cache._cache_pool.reserve() as cache:
            self.assertNotEqual(cache, 'CACHE_TEST')

    def test_multiple_context_managers_share_single_client(self):
        self.set_middleware()
        token_cache = self.middleware._token_cache
        env = {}
        token_cache.initialize(env)

        caches = []

        with token_cache._cache_pool.reserve() as cache:
            caches.append(cache)

        with token_cache._cache_pool.reserve() as cache:
            caches.append(cache)

        self.assertIs(caches[0], caches[1])
        self.assertEqual(set(caches), set(token_cache._cache_pool))

    def test_nested_context_managers_create_multiple_clients(self):
        self.set_middleware()
        env = {}
        self.middleware._token_cache.initialize(env)
        token_cache = self.middleware._token_cache

        with token_cache._cache_pool.reserve() as outer_cache:
            with token_cache._cache_pool.reserve() as inner_cache:
                self.assertNotEqual(outer_cache, inner_cache)

        self.assertEqual(
            set([inner_cache, outer_cache]),
            set(token_cache._cache_pool))


class GeneralAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                     testresources.ResourcedTestCase):
    """These tests are not affected by the token format
    (see CommonAuthTokenMiddlewareTest).
    """

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def test_token_is_v2_accepts_v2(self):
        token = self.examples.UUID_TOKEN_DEFAULT
        token_response = self.examples.TOKEN_RESPONSES[token]
        self.assertTrue(auth_token._token_is_v2(token_response))

    def test_token_is_v2_rejects_v3(self):
        token = self.examples.v3_UUID_TOKEN_DEFAULT
        token_response = self.examples.TOKEN_RESPONSES[token]
        self.assertFalse(auth_token._token_is_v2(token_response))

    def test_token_is_v3_rejects_v2(self):
        token = self.examples.UUID_TOKEN_DEFAULT
        token_response = self.examples.TOKEN_RESPONSES[token]
        self.assertFalse(auth_token._token_is_v3(token_response))

    def test_token_is_v3_accepts_v3(self):
        token = self.examples.v3_UUID_TOKEN_DEFAULT
        token_response = self.examples.TOKEN_RESPONSES[token]
        self.assertTrue(auth_token._token_is_v3(token_response))

    @testtools.skipUnless(memcached_available(), 'memcached not available')
    def test_encrypt_cache_data(self):
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'encrypt',
            'memcache_secret_key': 'mysecret'
        }
        self.set_middleware(conf=conf)
        token = b'my_token'
        some_time_later = timeutils.utcnow() + datetime.timedelta(hours=4)
        expires = timeutils.strtime(some_time_later)
        data = ('this_data', expires)
        token_cache = self.middleware._token_cache
        token_cache.initialize({})
        token_cache._cache_store(token, data)
        self.assertEqual(token_cache._cache_get(token), data[0])

    @testtools.skipUnless(memcached_available(), 'memcached not available')
    def test_sign_cache_data(self):
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mac',
            'memcache_secret_key': 'mysecret'
        }
        self.set_middleware(conf=conf)
        token = b'my_token'
        some_time_later = timeutils.utcnow() + datetime.timedelta(hours=4)
        expires = timeutils.strtime(some_time_later)
        data = ('this_data', expires)
        token_cache = self.middleware._token_cache
        token_cache.initialize({})
        token_cache._cache_store(token, data)
        self.assertEqual(token_cache._cache_get(token), data[0])

    @testtools.skipUnless(memcached_available(), 'memcached not available')
    def test_no_memcache_protection(self):
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_secret_key': 'mysecret'
        }
        self.set_middleware(conf=conf)
        token = 'my_token'
        some_time_later = timeutils.utcnow() + datetime.timedelta(hours=4)
        expires = timeutils.strtime(some_time_later)
        data = ('this_data', expires)
        token_cache = self.middleware._token_cache
        token_cache.initialize({})
        token_cache._cache_store(token, data)
        self.assertEqual(token_cache._cache_get(token), data[0])

    def test_assert_valid_memcache_protection_config(self):
        # test missing memcache_secret_key
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'Encrypt'
        }
        self.assertRaises(auth_token.ConfigurationError, self.set_middleware,
                          conf=conf)
        # test invalue memcache_security_strategy
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'whatever'
        }
        self.assertRaises(auth_token.ConfigurationError, self.set_middleware,
                          conf=conf)
        # test missing memcache_secret_key
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mac'
        }
        self.assertRaises(auth_token.ConfigurationError, self.set_middleware,
                          conf=conf)
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'Encrypt',
            'memcache_secret_key': ''
        }
        self.assertRaises(auth_token.ConfigurationError, self.set_middleware,
                          conf=conf)
        conf = {
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mAc',
            'memcache_secret_key': ''
        }
        self.assertRaises(auth_token.ConfigurationError, self.set_middleware,
                          conf=conf)

    def test_config_revocation_cache_timeout(self):
        conf = {
            'revocation_cache_time': '24',
            'auth_uri': 'https://keystone.example.com:1234',
            'admin_user': uuid.uuid4().hex
        }
        middleware = auth_token.AuthProtocol(self.fake_app, conf)
        self.assertEqual(middleware._token_revocation_list_cache_timeout,
                         datetime.timedelta(seconds=24))

    def test_conf_values_type_convert(self):
        conf = {
            'revocation_cache_time': '24',
            'identity_uri': 'https://keystone.example.com:1234',
            'include_service_catalog': '0',
            'nonexsit_option': '0',
        }

        middleware = auth_token.AuthProtocol(self.fake_app, conf)
        self.assertEqual(datetime.timedelta(seconds=24),
                         middleware._token_revocation_list_cache_timeout)
        self.assertEqual(False, middleware._include_service_catalog)
        self.assertEqual('0', middleware._conf['nonexsit_option'])

    def test_deprecated_conf_values(self):
        conf = {
            'memcache_servers': ','.join(MEMCACHED_SERVERS),
        }

        middleware = auth_token.AuthProtocol(self.fake_app, conf)
        self.assertEqual(MEMCACHED_SERVERS,
                         middleware._conf_get('memcached_servers'))

    def test_conf_values_type_convert_with_wrong_value(self):
        conf = {
            'include_service_catalog': '123',
        }
        self.assertRaises(auth_token.ConfigurationError,
                          auth_token.AuthProtocol, self.fake_app, conf)


class CommonAuthTokenMiddlewareTest(object):
    """These tests are run once using v2 tokens and again using v3 tokens."""

    def test_init_does_not_call_http(self):
        conf = {
            'revocation_cache_time': '1'
        }
        self.set_middleware(conf=conf)
        self.assertLastPath(None)

    def test_auth_with_no_token_does_not_call_http(self):
        self.set_middleware()
        req = webob.Request.blank('/')
        self.middleware(req.environ, self.start_fake_response)
        self.assertLastPath(None)
        self.assertEqual(401, self.response_status)

    def test_init_by_ipv6Addr_auth_host(self):
        del self.conf['identity_uri']
        conf = {
            'auth_host': '2001:2013:1:f101::1',
            'auth_port': '1234',
            'auth_protocol': 'http',
            'auth_uri': None,
            'auth_version': 'v3.0',
        }
        self.set_middleware(conf=conf)
        expected_auth_uri = 'http://[2001:2013:1:f101::1]:1234'
        self.assertEqual(expected_auth_uri,
                         self.middleware._auth_uri)

    def assert_valid_request_200(self, token, with_catalog=True):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        if with_catalog:
            self.assertTrue(req.headers.get('X-Service-Catalog'))
        else:
            self.assertNotIn('X-Service-Catalog', req.headers)
        self.assertEqual(body, [FakeApp.SUCCESS])
        self.assertIn('keystone.token_info', req.environ)
        return req

    def test_valid_uuid_request(self):
        for _ in range(2):  # Do it twice because first result was cached.
            token = self.token_dict['uuid_token_default']
            self.assert_valid_request_200(token)
            self.assert_valid_last_url(token)

    def test_valid_uuid_request_with_auth_fragments(self):
        del self.conf['identity_uri']
        self.conf['auth_protocol'] = 'https'
        self.conf['auth_host'] = 'keystone.example.com'
        self.conf['auth_port'] = '1234'
        self.conf['auth_admin_prefix'] = '/testadmin'
        self.set_middleware()
        self.assert_valid_request_200(self.token_dict['uuid_token_default'])
        self.assert_valid_last_url(self.token_dict['uuid_token_default'])

    def _test_cache_revoked(self, token, revoked_form=None):
        # When the token is cached and revoked, 401 is returned.
        self.middleware._check_revocations_for_cached = True

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token

        # Token should be cached as ok after this.
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)

        # Put it in revocation list.
        self.middleware._token_revocation_list = self.get_revocation_list_json(
            token_ids=[revoked_form or token])
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)

    def test_cached_revoked_uuid(self):
        # When the UUID token is cached and revoked, 401 is returned.
        self._test_cache_revoked(self.token_dict['uuid_token_default'])

    def test_valid_signed_request(self):
        for _ in range(2):  # Do it twice because first result was cached.
            self.assert_valid_request_200(
                self.token_dict['signed_token_scoped'])
            # ensure that signed requests do not generate HTTP traffic
            self.assertLastPath(None)

    def test_valid_signed_compressed_request(self):
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])
        # ensure that signed requests do not generate HTTP traffic
        self.assertLastPath(None)

    def test_revoked_token_receives_401(self):
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['revoked_token']
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)

    def test_revoked_token_receives_401_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json(mode='sha256'))
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['revoked_token']
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)

    def test_cached_revoked_pki(self):
        # When the PKI token is cached and revoked, 401 is returned.
        token = self.token_dict['signed_token_scoped']
        revoked_form = cms.cms_hash_token(token)
        self._test_cache_revoked(token, revoked_form)

    def test_cached_revoked_pkiz(self):
        # When the PKIZ token is cached and revoked, 401 is returned.
        token = self.token_dict['signed_token_scoped_pkiz']
        revoked_form = cms.cms_hash_token(token)
        self._test_cache_revoked(token, revoked_form)

    def test_revoked_token_receives_401_md5_secondary(self):
        # When hash_algorithms has 'md5' as the secondary hash and the
        # revocation list contains the md5 hash for a token, that token is
        # considered revoked so returns 401.
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['revoked_token']
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)

    def _test_revoked_hashed_token(self, token_name):
        # If hash_algorithms is set as ['sha256', 'md5'],
        # and check_revocations_for_cached is True,
        # and a token is in the cache because it was successfully validated
        # using the md5 hash, then
        # if the token is in the revocation list by md5 hash, it'll be
        # rejected and auth_token returns 401.
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.conf['check_revocations_for_cached'] = 'true'
        self.set_middleware()

        token = self.token_dict[token_name]

        # Put the token in the revocation list.
        token_hashed = cms.cms_hash_token(token)
        self.middleware._token_revocation_list = self.get_revocation_list_json(
            token_ids=[token_hashed])

        # First, request is using the hashed token, is valid so goes in
        # cache using the given hash.
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token_hashed
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)

        # This time use the PKI(Z) token
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)

        # Should find the token in the cache and revocation list.
        self.assertEqual(401, self.response_status)

    def test_revoked_hashed_pki_token(self):
        self._test_revoked_hashed_token('signed_token_scoped')

    def test_revoked_hashed_pkiz_token(self):
        self._test_revoked_hashed_token('signed_token_scoped_pkiz')

    def get_revocation_list_json(self, token_ids=None, mode=None):
        if token_ids is None:
            key = 'revoked_token_hash' + (('_' + mode) if mode else '')
            token_ids = [self.token_dict[key]]
        revocation_list = {'revoked': [{'id': x, 'expires': timeutils.utcnow()}
                                       for x in token_ids]}
        return jsonutils.dumps(revocation_list)

    def test_is_signed_token_revoked_returns_false(self):
        # explicitly setting an empty revocation list here to document intent
        self.middleware._token_revocation_list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})
        result = self.middleware._is_signed_token_revoked(
            [self.token_dict['revoked_token_hash']])
        self.assertFalse(result)

    def test_is_signed_token_revoked_returns_true(self):
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        result = self.middleware._is_signed_token_revoked(
            [self.token_dict['revoked_token_hash']])
        self.assertTrue(result)

    def test_is_signed_token_revoked_returns_true_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json(mode='sha256'))
        result = self.middleware._is_signed_token_revoked(
            [self.token_dict['revoked_token_hash_sha256']])
        self.assertTrue(result)

    def test_verify_signed_token_raises_exception_for_revoked_token(self):
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        self.assertRaises(auth_token.InvalidToken,
                          self.middleware._verify_signed_token,
                          self.token_dict['revoked_token'],
                          [self.token_dict['revoked_token_hash']])

    def test_verify_signed_token_raises_exception_for_revoked_token_s256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json(mode='sha256'))
        self.assertRaises(auth_token.InvalidToken,
                          self.middleware._verify_signed_token,
                          self.token_dict['revoked_token'],
                          [self.token_dict['revoked_token_hash_sha256'],
                           self.token_dict['revoked_token_hash']])

    def test_verify_signed_token_raises_exception_for_revoked_pkiz_token(self):
        self.middleware._token_revocation_list = (
            self.examples.REVOKED_TOKEN_PKIZ_LIST_JSON)
        self.assertRaises(auth_token.InvalidToken,
                          self.middleware._verify_pkiz_token,
                          self.token_dict['revoked_token_pkiz'],
                          [self.token_dict['revoked_token_pkiz_hash']])

    def assertIsValidJSON(self, text):
        json.loads(text)

    def test_verify_signed_token_succeeds_for_unrevoked_token(self):
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        text = self.middleware._verify_signed_token(
            self.token_dict['signed_token_scoped'],
            [self.token_dict['signed_token_scoped_hash']])
        self.assertIsValidJSON(text)

    def test_verify_signed_compressed_token_succeeds_for_unrevoked_token(self):
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json())
        text = self.middleware._verify_pkiz_token(
            self.token_dict['signed_token_scoped_pkiz'],
            [self.token_dict['signed_token_scoped_hash']])
        self.assertIsValidJSON(text)

    def test_verify_signed_token_succeeds_for_unrevoked_token_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._token_revocation_list = (
            self.get_revocation_list_json(mode='sha256'))
        text = self.middleware._verify_signed_token(
            self.token_dict['signed_token_scoped'],
            [self.token_dict['signed_token_scoped_hash_sha256'],
             self.token_dict['signed_token_scoped_hash']])
        self.assertIsValidJSON(text)

    def test_verify_signing_dir_create_while_missing(self):
        tmp_name = uuid.uuid4().hex
        test_parent_signing_dir = "/tmp/%s" % tmp_name
        self.middleware._signing_dirname = "/tmp/%s/%s" % ((tmp_name,) * 2)
        self.middleware._signing_cert_file_name = (
            "%s/test.pem" % self.middleware._signing_dirname)
        self.middleware._verify_signing_dir()
        # NOTE(wu_wenxiang): Verify if the signing dir was created as expected.
        self.assertTrue(os.path.isdir(self.middleware._signing_dirname))
        self.assertTrue(os.access(self.middleware._signing_dirname, os.W_OK))
        self.assertEqual(os.stat(self.middleware._signing_dirname).st_uid,
                         os.getuid())
        self.assertEqual(
            stat.S_IMODE(os.stat(self.middleware._signing_dirname).st_mode),
            stat.S_IRWXU)
        shutil.rmtree(test_parent_signing_dir)

    def test_get_token_revocation_list_fetched_time_returns_min(self):
        self.middleware._token_revocation_list_fetched_time = None
        self.middleware._revoked_file_name = ''
        self.assertEqual(self.middleware._token_revocation_list_fetched_time,
                         datetime.datetime.min)

    def test_get_token_revocation_list_fetched_time_returns_mtime(self):
        self.middleware._token_revocation_list_fetched_time = None
        mtime = os.path.getmtime(self.middleware._revoked_file_name)
        fetched_time = datetime.datetime.utcfromtimestamp(mtime)
        self.assertEqual(fetched_time,
                         self.middleware._token_revocation_list_fetched_time)

    @testtools.skipUnless(TimezoneFixture.supported(),
                          'TimezoneFixture not supported')
    def test_get_token_revocation_list_fetched_time_returns_utc(self):
        with TimezoneFixture('UTC-1'):
            self.middleware._token_revocation_list = jsonutils.dumps(
                self.examples.REVOCATION_LIST)
            self.middleware._token_revocation_list_fetched_time = None
            fetched_time = self.middleware._token_revocation_list_fetched_time
            self.assertTrue(timeutils.is_soon(fetched_time, 1))

    def test_get_token_revocation_list_fetched_time_returns_value(self):
        expected = self.middleware._token_revocation_list_fetched_time
        self.assertEqual(self.middleware._token_revocation_list_fetched_time,
                         expected)

    def test_get_revocation_list_returns_fetched_list(self):
        # auth_token uses v2 to fetch this, so don't allow the v3
        # tests to override the fake http connection
        self.middleware._token_revocation_list_fetched_time = None
        os.remove(self.middleware._revoked_file_name)
        self.assertEqual(self.middleware._token_revocation_list,
                         self.examples.REVOCATION_LIST)

    def test_get_revocation_list_returns_current_list_from_memory(self):
        self.assertEqual(self.middleware._token_revocation_list,
                         self.middleware._token_revocation_list_prop)

    def test_get_revocation_list_returns_current_list_from_disk(self):
        in_memory_list = self.middleware._token_revocation_list
        self.middleware._token_revocation_list_prop = None
        self.assertEqual(self.middleware._token_revocation_list,
                         in_memory_list)

    def test_invalid_revocation_list_raises_error(self):
        self.requests.get('%s/v2.0/tokens/revoked' % BASE_URI, json={})

        self.assertRaises(auth_token.RevocationListError,
                          self.middleware._fetch_revocation_list)

    def test_fetch_revocation_list(self):
        # auth_token uses v2 to fetch this, so don't allow the v3
        # tests to override the fake http connection
        fetched = jsonutils.loads(self.middleware._fetch_revocation_list())
        self.assertEqual(fetched, self.examples.REVOCATION_LIST)

    def test_request_invalid_uuid_token(self):
        # remember because we are testing the middleware we stub the connection
        # to the keystone server, but this is not what gets returned
        invalid_uri = "%s/v2.0/tokens/invalid-token" % BASE_URI
        self.requests.get(invalid_uri, status_code=404)

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = 'invalid-token'
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         "Keystone uri='https://keystone.example.com:1234'")

    def test_request_invalid_signed_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.examples.INVALID_SIGNED_TOKEN
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         self.response_headers['WWW-Authenticate'])

    def test_request_invalid_signed_pkiz_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.examples.INVALID_SIGNED_PKIZ_TOKEN
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         self.response_headers['WWW-Authenticate'])

    def test_request_no_token(self):
        req = webob.Request.blank('/')
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         "Keystone uri='https://keystone.example.com:1234'")

    def test_request_no_token_log_message(self):
        class FakeLog(object):
            def __init__(self):
                self.msg = None
                self.debugmsg = None

            def warn(self, msg=None, *args, **kwargs):
                self.msg = msg

            def debug(self, msg=None, *args, **kwargs):
                self.debugmsg = msg

        self.middleware._LOG = FakeLog()
        self.middleware._delay_auth_decision = False
        self.assertRaises(auth_token.InvalidToken,
                          self.middleware._get_user_token_from_header, {})
        self.assertIsNotNone(self.middleware._LOG.msg)
        self.assertIsNotNone(self.middleware._LOG.debugmsg)

    def test_request_no_token_http(self):
        req = webob.Request.blank('/', environ={'REQUEST_METHOD': 'HEAD'})
        self.set_middleware()
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         "Keystone uri='https://keystone.example.com:1234'")
        self.assertEqual(body, [''])

    def test_request_blank_token(self):
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = ''
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         "Keystone uri='https://keystone.example.com:1234'")

    def _get_cached_token(self, token, mode='md5'):
        token_id = cms.cms_hash_token(token, mode=mode)
        return self.middleware._token_cache._cache_get(token_id)

    def test_memcache(self):
        req = webob.Request.blank('/')
        token = self.token_dict['signed_token_scoped']
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertIsNotNone(self._get_cached_token(token))

    def test_expired(self):
        req = webob.Request.blank('/')
        token = self.token_dict['signed_token_scoped_expired']
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)

    def test_memcache_set_invalid_uuid(self):
        invalid_uri = "%s/v2.0/tokens/invalid-token" % BASE_URI
        self.requests.get(invalid_uri, status_code=404)

        req = webob.Request.blank('/')
        token = 'invalid-token'
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertRaises(auth_token.InvalidToken,
                          self._get_cached_token, token)

    def _test_memcache_set_invalid_signed(self, hash_algorithms=None,
                                          exp_mode='md5'):
        req = webob.Request.blank('/')
        token = self.token_dict['signed_token_scoped_expired']
        req.headers['X-Auth-Token'] = token
        if hash_algorithms:
            self.conf['hash_algorithms'] = ','.join(hash_algorithms)
            self.set_middleware()
        self.middleware(req.environ, self.start_fake_response)
        self.assertRaises(auth_token.InvalidToken,
                          self._get_cached_token, token, mode=exp_mode)

    def test_memcache_set_invalid_signed(self):
        self._test_memcache_set_invalid_signed()

    def test_memcache_set_invalid_signed_sha256_md5(self):
        hash_algorithms = ['sha256', 'md5']
        self._test_memcache_set_invalid_signed(hash_algorithms=hash_algorithms,
                                               exp_mode='sha256')

    def test_memcache_set_invalid_signed_sha256(self):
        hash_algorithms = ['sha256']
        self._test_memcache_set_invalid_signed(hash_algorithms=hash_algorithms,
                                               exp_mode='sha256')

    def test_memcache_set_expired(self, extra_conf={}, extra_environ={}):
        token_cache_time = 10
        conf = {
            'token_cache_time': '%s' % token_cache_time,
        }
        conf.update(extra_conf)
        self.set_middleware(conf=conf)
        req = webob.Request.blank('/')
        token = self.token_dict['signed_token_scoped']
        req.headers['X-Auth-Token'] = token
        req.environ.update(extra_environ)

        now = datetime.datetime.utcnow()
        self.useFixture(TimeFixture(now))
        self.middleware(req.environ, self.start_fake_response)
        self.assertIsNotNone(self._get_cached_token(token))

        timeutils.advance_time_seconds(token_cache_time)
        self.assertIsNone(self._get_cached_token(token))

    def test_swift_memcache_set_expired(self):
        extra_conf = {'cache': 'swift.cache'}
        extra_environ = {'swift.cache': memorycache.Client()}
        self.test_memcache_set_expired(extra_conf, extra_environ)

    def test_http_error_not_cached_token(self):
        """Test to don't cache token as invalid on network errors.

        We use UUID tokens since they are the easiest one to reach
        get_http_connection.
        """
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = ERROR_TOKEN
        self.middleware._http_request_max_retries = 0
        self.middleware(req.environ, self.start_fake_response)
        self.assertIsNone(self._get_cached_token(ERROR_TOKEN))
        self.assert_valid_last_url(ERROR_TOKEN)

    def test_http_request_max_retries(self):
        times_retry = 10

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = ERROR_TOKEN

        conf = {'http_request_max_retries': '%s' % times_retry}
        self.set_middleware(conf=conf)

        with mock.patch('time.sleep') as mock_obj:
            self.middleware(req.environ, self.start_fake_response)

        self.assertEqual(mock_obj.call_count, times_retry)

    def test_nocatalog(self):
        conf = {
            'include_service_catalog': 'False'
        }
        self.set_middleware(conf=conf)
        self.assert_valid_request_200(self.token_dict['uuid_token_default'],
                                      with_catalog=False)

    def assert_kerberos_bind(self, token, bind_level,
                             use_kerberos=True, success=True):
        conf = {
            'enforce_token_bind': bind_level,
            'auth_version': self.auth_version,
        }
        self.set_middleware(conf=conf)

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token

        if use_kerberos:
            if use_kerberos is True:
                req.environ['REMOTE_USER'] = self.examples.KERBEROS_BIND
            else:
                req.environ['REMOTE_USER'] = use_kerberos

            req.environ['AUTH_TYPE'] = 'Negotiate'

        body = self.middleware(req.environ, self.start_fake_response)

        if success:
            self.assertEqual(self.response_status, 200)
            self.assertEqual(body, [FakeApp.SUCCESS])
            self.assertIn('keystone.token_info', req.environ)
            self.assert_valid_last_url(token)
        else:
            self.assertEqual(self.response_status, 401)
            self.assertEqual(self.response_headers['WWW-Authenticate'],
                             "Keystone uri='https://keystone.example.com:1234'"
                             )

    def test_uuid_bind_token_disabled_with_kerb_user(self):
        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                      bind_level='disabled',
                                      use_kerberos=use_kerberos,
                                      success=True)

    def test_uuid_bind_token_disabled_with_incorrect_ticket(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='kerberos',
                                  use_kerberos='ronald@MCDONALDS.COM',
                                  success=False)

    def test_uuid_bind_token_permissive_with_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='permissive',
                                  use_kerberos=True,
                                  success=True)

    def test_uuid_bind_token_permissive_without_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='permissive',
                                  use_kerberos=False,
                                  success=False)

    def test_uuid_bind_token_permissive_with_unknown_bind(self):
        token = self.token_dict['uuid_token_unknown_bind']

        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(token,
                                      bind_level='permissive',
                                      use_kerberos=use_kerberos,
                                      success=True)

    def test_uuid_bind_token_permissive_with_incorrect_ticket(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='kerberos',
                                  use_kerberos='ronald@MCDONALDS.COM',
                                  success=False)

    def test_uuid_bind_token_strict_with_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='strict',
                                  use_kerberos=True,
                                  success=True)

    def test_uuid_bind_token_strict_with_kerbout_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='strict',
                                  use_kerberos=False,
                                  success=False)

    def test_uuid_bind_token_strict_with_unknown_bind(self):
        token = self.token_dict['uuid_token_unknown_bind']

        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(token,
                                      bind_level='strict',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_uuid_bind_token_required_with_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='required',
                                  use_kerberos=True,
                                  success=True)

    def test_uuid_bind_token_required_without_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='required',
                                  use_kerberos=False,
                                  success=False)

    def test_uuid_bind_token_required_with_unknown_bind(self):
        token = self.token_dict['uuid_token_unknown_bind']

        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(token,
                                      bind_level='required',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_uuid_bind_token_required_without_bind(self):
        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(self.token_dict['uuid_token_default'],
                                      bind_level='required',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_uuid_bind_token_named_kerberos_with_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='kerberos',
                                  use_kerberos=True,
                                  success=True)

    def test_uuid_bind_token_named_kerberos_without_kerb_user(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='kerberos',
                                  use_kerberos=False,
                                  success=False)

    def test_uuid_bind_token_named_kerberos_with_unknown_bind(self):
        token = self.token_dict['uuid_token_unknown_bind']

        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(token,
                                      bind_level='kerberos',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_uuid_bind_token_named_kerberos_without_bind(self):
        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(self.token_dict['uuid_token_default'],
                                      bind_level='kerberos',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_uuid_bind_token_named_kerberos_with_incorrect_ticket(self):
        self.assert_kerberos_bind(self.token_dict['uuid_token_bind'],
                                  bind_level='kerberos',
                                  use_kerberos='ronald@MCDONALDS.COM',
                                  success=False)

    def test_uuid_bind_token_with_unknown_named_FOO(self):
        token = self.token_dict['uuid_token_bind']

        for use_kerberos in [True, False]:
            self.assert_kerberos_bind(token,
                                      bind_level='FOO',
                                      use_kerberos=use_kerberos,
                                      success=False)

    def test_caching_token_on_verify(self):
        # When the token is cached it isn't cached again when it's verified.

        # The token cache has to be initialized with our cache instance.
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = memorycache.Client()
        self.middleware._token_cache.initialize(env={'cache': cache})

        # Mock cache.set since then the test can verify call_count.
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        token = self.token_dict['signed_token_scoped']

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)

        self.assertThat(1, matchers.Equals(cache.set.call_count))

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)

        # Assert that the token wasn't cached again.
        self.assertThat(1, matchers.Equals(cache.set.call_count))

    def test_auth_plugin(self):

        for service_url in (self.examples.UNVERSIONED_SERVICE_URL,
                            self.examples.SERVICE_URL):
            self.requests.get(service_url,
                              json=VERSION_LIST_v3,
                              status_code=300)

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['uuid_token_default']
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)
        self.assertEqual([FakeApp.SUCCESS], body)

        token_auth = req.environ['keystone.token_auth']
        endpoint_filter = {'service_type': self.examples.SERVICE_TYPE,
                           'version': 3}

        url = token_auth.get_endpoint(session.Session(), **endpoint_filter)
        self.assertEqual('%s/v3' % BASE_URI, url)

        self.assertTrue(token_auth.has_user_token)
        self.assertFalse(token_auth.has_service_token)
        self.assertIsNone(token_auth.service)


class V2CertDownloadMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                   testresources.ResourcedTestCase):

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def __init__(self, *args, **kwargs):
        super(V2CertDownloadMiddlewareTest, self).__init__(*args, **kwargs)
        self.auth_version = 'v2.0'
        self.fake_app = None
        self.ca_path = '/v2.0/certificates/ca'
        self.signing_path = '/v2.0/certificates/signing'

    def setUp(self):
        super(V2CertDownloadMiddlewareTest, self).setUp(
            auth_version=self.auth_version,
            fake_app=self.fake_app)
        self.base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base_dir)
        self.cert_dir = os.path.join(self.base_dir, 'certs')
        os.makedirs(self.cert_dir, stat.S_IRWXU)
        conf = {
            'signing_dir': self.cert_dir,
            'auth_version': self.auth_version,
        }

        self.requests.register_uri('GET',
                                   BASE_URI,
                                   json=VERSION_LIST_v3,
                                   status_code=300)

        self.set_middleware(conf=conf)

    # Usually we supply a signed_dir with pre-installed certificates,
    # so invocation of /usr/bin/openssl succeeds. This time we give it
    # an empty directory, so it fails.
    def test_request_no_token_dummy(self):
        cms._ensure_subprocess()

        self.requests.get('%s%s' % (BASE_URI, self.ca_path),
                          status_code=404)
        self.requests.get('%s%s' % (BASE_URI, self.signing_path),
                          status_code=404)
        self.assertRaises(exceptions.CertificateConfigError,
                          self.middleware._verify_signed_token,
                          self.examples.SIGNED_TOKEN_SCOPED,
                          [self.examples.SIGNED_TOKEN_SCOPED_HASH])

    def test_fetch_signing_cert(self):
        data = 'FAKE CERT'
        url = "%s%s" % (BASE_URI, self.signing_path)
        self.requests.get(url, text=data)
        self.middleware._fetch_signing_cert()

        with open(self.middleware._signing_cert_file_name, 'r') as f:
            self.assertEqual(f.read(), data)

        self.assertEqual(url, self.requests.last_request.url)

    def test_fetch_signing_ca(self):
        data = 'FAKE CA'
        url = "%s%s" % (BASE_URI, self.ca_path)
        self.requests.get(url, text=data)
        self.middleware._fetch_ca_cert()

        with open(self.middleware._signing_ca_file_name, 'r') as f:
            self.assertEqual(f.read(), data)

        self.assertEqual(url, self.requests.last_request.url)

    def test_prefix_trailing_slash(self):
        del self.conf['identity_uri']
        self.conf['auth_protocol'] = 'https'
        self.conf['auth_host'] = 'keystone.example.com'
        self.conf['auth_port'] = '1234'
        self.conf['auth_admin_prefix'] = '/newadmin/'

        base_url = '%s/newadmin' % BASE_HOST
        ca_url = "%s%s" % (base_url, self.ca_path)
        signing_url = "%s%s" % (base_url, self.signing_path)

        self.requests.get(base_url,
                          json=VERSION_LIST_v3,
                          status_code=300)
        self.requests.get(ca_url, text='FAKECA')
        self.requests.get(signing_url, text='FAKECERT')

        self.set_middleware(conf=self.conf)

        self.middleware._fetch_ca_cert()
        self.assertEqual(ca_url, self.requests.last_request.url)

        self.middleware._fetch_signing_cert()
        self.assertEqual(signing_url, self.requests.last_request.url)

    def test_without_prefix(self):
        del self.conf['identity_uri']
        self.conf['auth_protocol'] = 'https'
        self.conf['auth_host'] = 'keystone.example.com'
        self.conf['auth_port'] = '1234'
        self.conf['auth_admin_prefix'] = ''

        ca_url = "%s%s" % (BASE_HOST, self.ca_path)
        signing_url = "%s%s" % (BASE_HOST, self.signing_path)

        self.requests.get(BASE_HOST,
                          json=VERSION_LIST_v3,
                          status_code=300)
        self.requests.get(ca_url, text='FAKECA')
        self.requests.get(signing_url, text='FAKECERT')

        self.set_middleware(conf=self.conf)

        self.middleware._fetch_ca_cert()
        self.assertEqual(ca_url, self.requests.last_request.url)

        self.middleware._fetch_signing_cert()
        self.assertEqual(signing_url, self.requests.last_request.url)


class V3CertDownloadMiddlewareTest(V2CertDownloadMiddlewareTest):

    def __init__(self, *args, **kwargs):
        super(V3CertDownloadMiddlewareTest, self).__init__(*args, **kwargs)
        self.auth_version = 'v3.0'
        self.fake_app = v3FakeApp
        self.ca_path = '/v3/OS-SIMPLE-CERT/ca'
        self.signing_path = '/v3/OS-SIMPLE-CERT/certificates'


def network_error_response(request, context):
    raise exceptions.ConnectionError("Network connection error.")


class v2AuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                CommonAuthTokenMiddlewareTest,
                                testresources.ResourcedTestCase):
    """v2 token specific tests.

    There are some differences between how the auth-token middleware handles
    v2 and v3 tokens over and above the token formats, namely:

    - A v3 keystone server will auto scope a token to a user's default project
      if no scope is specified. A v2 server assumes that the auth-token
      middleware will do that.
    - A v2 keystone server may issue a token without a catalog, even with a
      tenant

    The tests below were originally part of the generic AuthTokenMiddlewareTest
    class, but now, since they really are v2 specific, they are included here.

    """

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(v2AuthTokenMiddlewareTest, self).setUp()

        self.token_dict = {
            'uuid_token_default': self.examples.UUID_TOKEN_DEFAULT,
            'uuid_token_unscoped': self.examples.UUID_TOKEN_UNSCOPED,
            'uuid_token_bind': self.examples.UUID_TOKEN_BIND,
            'uuid_token_unknown_bind': self.examples.UUID_TOKEN_UNKNOWN_BIND,
            'signed_token_scoped': self.examples.SIGNED_TOKEN_SCOPED,
            'signed_token_scoped_pkiz': self.examples.SIGNED_TOKEN_SCOPED_PKIZ,
            'signed_token_scoped_hash': self.examples.SIGNED_TOKEN_SCOPED_HASH,
            'signed_token_scoped_hash_sha256':
            self.examples.SIGNED_TOKEN_SCOPED_HASH_SHA256,
            'signed_token_scoped_expired':
            self.examples.SIGNED_TOKEN_SCOPED_EXPIRED,
            'revoked_token': self.examples.REVOKED_TOKEN,
            'revoked_token_pkiz': self.examples.REVOKED_TOKEN_PKIZ,
            'revoked_token_pkiz_hash':
            self.examples.REVOKED_TOKEN_PKIZ_HASH,
            'revoked_token_hash': self.examples.REVOKED_TOKEN_HASH,
            'revoked_token_hash_sha256':
            self.examples.REVOKED_TOKEN_HASH_SHA256,
        }

        self.requests.get(BASE_URI,
                          json=VERSION_LIST_v2,
                          status_code=300)

        self.requests.post('%s/v2.0/tokens' % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        self.requests.get('%s/v2.0/tokens/revoked' % BASE_URI,
                          text=self.examples.SIGNED_REVOCATION_LIST)

        for token in (self.examples.UUID_TOKEN_DEFAULT,
                      self.examples.UUID_TOKEN_UNSCOPED,
                      self.examples.UUID_TOKEN_BIND,
                      self.examples.UUID_TOKEN_UNKNOWN_BIND,
                      self.examples.UUID_TOKEN_NO_SERVICE_CATALOG,
                      self.examples.SIGNED_TOKEN_SCOPED_KEY,
                      self.examples.SIGNED_TOKEN_SCOPED_PKIZ_KEY,):
            url = "%s/v2.0/tokens/%s" % (BASE_URI, token)
            text = self.examples.JSON_TOKEN_RESPONSES[token]
            self.requests.get(url, text=text)

        url = '%s/v2.0/tokens/%s' % (BASE_URI, ERROR_TOKEN)
        self.requests.get(url, text=network_error_response)

        self.set_middleware()

    def assert_unscoped_default_tenant_auto_scopes(self, token):
        """Unscoped v2 requests with a default tenant should "auto-scope."

        The implied scope is the user's tenant ID.

        """
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(body, [FakeApp.SUCCESS])
        self.assertIn('keystone.token_info', req.environ)

    def assert_valid_last_url(self, token_id):
        self.assertLastPath("/v2.0/tokens/%s" % token_id)

    def test_default_tenant_uuid_token(self):
        self.assert_unscoped_default_tenant_auto_scopes(
            self.examples.UUID_TOKEN_DEFAULT)

    def test_default_tenant_signed_token(self):
        self.assert_unscoped_default_tenant_auto_scopes(
            self.examples.SIGNED_TOKEN_SCOPED)

    def assert_unscoped_token_receives_401(self, token):
        """Unscoped requests with no default tenant ID should be rejected."""
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 401)
        self.assertEqual(self.response_headers['WWW-Authenticate'],
                         "Keystone uri='https://keystone.example.com:1234'")

    def test_unscoped_uuid_token_receives_401(self):
        self.assert_unscoped_token_receives_401(
            self.examples.UUID_TOKEN_UNSCOPED)

    def test_unscoped_pki_token_receives_401(self):
        self.assert_unscoped_token_receives_401(
            self.examples.SIGNED_TOKEN_UNSCOPED)

    def test_request_prevent_service_catalog_injection(self):
        req = webob.Request.blank('/')
        req.headers['X-Service-Catalog'] = '[]'
        req.headers['X-Auth-Token'] = (
            self.examples.UUID_TOKEN_NO_SERVICE_CATALOG)
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertFalse(req.headers.get('X-Service-Catalog'))
        self.assertEqual(body, [FakeApp.SUCCESS])

    def test_user_plugin_token_properties(self):
        req = webob.Request.blank('/')
        req.headers['X-Service-Catalog'] = '[]'
        token = self.examples.UUID_TOKEN_DEFAULT
        token_data = self.examples.TOKEN_RESPONSES[token]
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = token

        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual([FakeApp.SUCCESS], body)

        token_auth = req.environ['keystone.token_auth']

        self.assertTrue(token_auth.has_user_token)
        self.assertTrue(token_auth.has_service_token)

        for t in [token_auth.user, token_auth.service]:
            self.assertEqual(token_data.user_id, t.user_id)
            self.assertEqual(token_data.tenant_id, t.project_id)

            self.assertThat(t.role_names, matchers.HasLength(2))
            self.assertIn('role1', t.role_names)
            self.assertIn('role2', t.role_names)

            self.assertIsNone(t.trust_id)
            self.assertIsNone(t.user_domain_id)
            self.assertIsNone(t.project_domain_id)


class CrossVersionAuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                          testresources.ResourcedTestCase):

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def test_valid_uuid_request_forced_to_2_0(self):
        """Test forcing auth_token to use lower api version.

        By installing the v3 http hander, auth_token will be get
        a version list that looks like a v3 server - from which it
        would normally chose v3.0 as the auth version.  However, here
        we specify v2.0 in the configuration - which should force
        auth_token to use that version instead.

        """
        conf = {
            'auth_version': 'v2.0'
        }

        self.requests.get(BASE_URI,
                          json=VERSION_LIST_v3,
                          status_code=300)

        self.requests.post('%s/v2.0/tokens' % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        token = self.examples.UUID_TOKEN_DEFAULT
        url = "%s/v2.0/tokens/%s" % (BASE_URI, token)
        text = self.examples.JSON_TOKEN_RESPONSES[token]
        self.requests.get(url, text=text)

        self.set_middleware(conf=conf)

        # This tests will only work is auth_token has chosen to use the
        # lower, v2, api version
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.examples.UUID_TOKEN_DEFAULT
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual(url, self.requests.last_request.url)


class v3AuthTokenMiddlewareTest(BaseAuthTokenMiddlewareTest,
                                CommonAuthTokenMiddlewareTest,
                                testresources.ResourcedTestCase):
    """Test auth_token middleware with v3 tokens.

    Re-execute the AuthTokenMiddlewareTest class tests, but with the
    auth_token middleware configured to expect v3 tokens back from
    a keystone server.

    This is done by configuring the AuthTokenMiddlewareTest class via
    its Setup(), passing in v3 style data that will then be used by
    the tests themselves.  This approach has been used to ensure we
    really are running the same tests for both v2 and v3 tokens.

    There a few additional specific test for v3 only:

    - We allow an unscoped token to be validated (as unscoped), where
      as for v2 tokens, the auth_token middleware is expected to try and
      auto-scope it (and fail if there is no default tenant)
    - Domain scoped tokens

    Since we don't specify an auth version for auth_token to use, by
    definition we are thefore implicitely testing that it will use
    the highest available auth version, i.e. v3.0

    """

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(v3AuthTokenMiddlewareTest, self).setUp(
            auth_version='v3.0',
            fake_app=v3FakeApp)

        self.token_dict = {
            'uuid_token_default': self.examples.v3_UUID_TOKEN_DEFAULT,
            'uuid_token_unscoped': self.examples.v3_UUID_TOKEN_UNSCOPED,
            'uuid_token_bind': self.examples.v3_UUID_TOKEN_BIND,
            'uuid_token_unknown_bind':
            self.examples.v3_UUID_TOKEN_UNKNOWN_BIND,
            'signed_token_scoped': self.examples.SIGNED_v3_TOKEN_SCOPED,
            'signed_token_scoped_pkiz':
            self.examples.SIGNED_v3_TOKEN_SCOPED_PKIZ,
            'signed_token_scoped_hash':
            self.examples.SIGNED_v3_TOKEN_SCOPED_HASH,
            'signed_token_scoped_hash_sha256':
            self.examples.SIGNED_v3_TOKEN_SCOPED_HASH_SHA256,
            'signed_token_scoped_expired':
            self.examples.SIGNED_TOKEN_SCOPED_EXPIRED,
            'revoked_token': self.examples.REVOKED_v3_TOKEN,
            'revoked_token_pkiz': self.examples.REVOKED_v3_TOKEN_PKIZ,
            'revoked_token_hash': self.examples.REVOKED_v3_TOKEN_HASH,
            'revoked_token_hash_sha256':
            self.examples.REVOKED_v3_TOKEN_HASH_SHA256,
            'revoked_token_pkiz_hash':
            self.examples.REVOKED_v3_PKIZ_TOKEN_HASH,
        }

        self.requests.get(BASE_URI,
                          json=VERSION_LIST_v3,
                          status_code=300)

        # TODO(jamielennox): auth_token middleware uses a v2 admin token
        # regardless of the auth_version that is set.
        self.requests.post('%s/v2.0/tokens' % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        # TODO(jamielennox): there is no v3 revocation url yet, it uses v2
        self.requests.get('%s/v2.0/tokens/revoked' % BASE_URI,
                          text=self.examples.SIGNED_REVOCATION_LIST)

        self.requests.get('%s/v3/auth/tokens' % BASE_URI,
                          text=self.token_response)

        self.set_middleware()

    def token_response(self, request, context):
        auth_id = request.headers.get('X-Auth-Token')
        token_id = request.headers.get('X-Subject-Token')
        self.assertEqual(auth_id, FAKE_ADMIN_TOKEN_ID)

        if token_id == ERROR_TOKEN:
            raise exceptions.ConnectionError("Network connection error.")

        try:
            response = self.examples.JSON_TOKEN_RESPONSES[token_id]
        except KeyError:
            response = ""
            context.status_code = 404

        return response

    def assert_valid_last_url(self, token_id):
        self.assertLastPath('/v3/auth/tokens')

    def test_valid_unscoped_uuid_request(self):
        # Remove items that won't be in an unscoped token
        delta_expected_env = {
            'HTTP_X_PROJECT_ID': None,
            'HTTP_X_PROJECT_NAME': None,
            'HTTP_X_PROJECT_DOMAIN_ID': None,
            'HTTP_X_PROJECT_DOMAIN_NAME': None,
            'HTTP_X_TENANT_ID': None,
            'HTTP_X_TENANT_NAME': None,
            'HTTP_X_ROLES': '',
            'HTTP_X_TENANT': None,
            'HTTP_X_ROLE': '',
        }
        self.set_middleware(expected_env=delta_expected_env)
        self.assert_valid_request_200(self.examples.v3_UUID_TOKEN_UNSCOPED,
                                      with_catalog=False)
        self.assertLastPath('/v3/auth/tokens')

    def test_domain_scoped_uuid_request(self):
        # Modify items compared to default token for a domain scope
        delta_expected_env = {
            'HTTP_X_DOMAIN_ID': 'domain_id1',
            'HTTP_X_DOMAIN_NAME': 'domain_name1',
            'HTTP_X_PROJECT_ID': None,
            'HTTP_X_PROJECT_NAME': None,
            'HTTP_X_PROJECT_DOMAIN_ID': None,
            'HTTP_X_PROJECT_DOMAIN_NAME': None,
            'HTTP_X_TENANT_ID': None,
            'HTTP_X_TENANT_NAME': None,
            'HTTP_X_TENANT': None
        }
        self.set_middleware(expected_env=delta_expected_env)
        self.assert_valid_request_200(
            self.examples.v3_UUID_TOKEN_DOMAIN_SCOPED)
        self.assertLastPath('/v3/auth/tokens')

    def test_gives_v2_catalog(self):
        self.set_middleware()
        req = self.assert_valid_request_200(
            self.examples.SIGNED_v3_TOKEN_SCOPED)

        catalog = jsonutils.loads(req.headers['X-Service-Catalog'])

        for service in catalog:
            for endpoint in service['endpoints']:
                # no point checking everything, just that it's in v2 format
                self.assertIn('adminURL', endpoint)
                self.assertIn('publicURL', endpoint)
                self.assertIn('adminURL', endpoint)

    def test_fallback_to_online_validation_with_signing_error(self):
        self.requests.register_uri(
            'GET',
            '%s/v3/OS-SIMPLE-CERT/certificates' % BASE_URI,
            status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_fallback_to_online_validation_with_ca_error(self):
        self.requests.register_uri('GET',
                                   '%s/v3/OS-SIMPLE-CERT/ca' % BASE_URI,
                                   status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_fallback_to_online_validation_with_revocation_list_error(self):
        self.requests.register_uri('GET',
                                   '%s/v2.0/tokens/revoked' % BASE_URI,
                                   status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_user_plugin_token_properties(self):
        req = webob.Request.blank('/')
        req.headers['X-Service-Catalog'] = '[]'
        token = self.examples.v3_UUID_TOKEN_DEFAULT
        token_data = self.examples.TOKEN_RESPONSES[token]
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = token

        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(self.response_status, 200)
        self.assertEqual([FakeApp.SUCCESS], body)

        token_auth = req.environ['keystone.token_auth']

        self.assertTrue(token_auth.has_user_token)
        self.assertTrue(token_auth.has_service_token)

        for t in [token_auth.user, token_auth.service]:
            self.assertEqual(token_data.user_id, t.user_id)
            self.assertEqual(token_data.project_id, t.project_id)
            self.assertEqual(token_data.user_domain_id, t.user_domain_id)
            self.assertEqual(token_data.project_domain_id, t.project_domain_id)

            self.assertThat(t.role_names, matchers.HasLength(2))
            self.assertIn('role1', t.role_names)
            self.assertIn('role2', t.role_names)

            self.assertIsNone(t.trust_id)


class TokenEncodingTest(testtools.TestCase):
    def test_unquoted_token(self):
        self.assertEqual('foo%20bar', auth_token._safe_quote('foo bar'))

    def test_quoted_token(self):
        self.assertEqual('foo%20bar', auth_token._safe_quote('foo%20bar'))

    def test_messages_encoded_as_bytes(self):
        """Test that string are passed around as bytes for PY3."""
        msg = "This is an error"

        class FakeResp(auth_token._MiniResp):
            def __init__(self, error, env):
                super(FakeResp, self).__init__(error, env)

        fake_resp = FakeResp(msg, dict(REQUEST_METHOD='GET'))
        # On Py2 .encode() don't do much but that's better than to
        # have a ifdef with six.PY3
        self.assertEqual(msg.encode(), fake_resp.body[0])


class TokenExpirationTest(BaseAuthTokenMiddlewareTest):
    def setUp(self):
        super(TokenExpirationTest, self).setUp()
        self.now = timeutils.utcnow()
        self.delta = datetime.timedelta(hours=1)
        self.one_hour_ago = timeutils.isotime(self.now - self.delta,
                                              subsecond=True)
        self.one_hour_earlier = timeutils.isotime(self.now + self.delta,
                                                  subsecond=True)

    def create_v2_token_fixture(self, expires=None):
        v2_fixture = {
            'access': {
                'token': {
                    'id': 'blah',
                    'expires': expires or self.one_hour_earlier,
                    'tenant': {
                        'id': 'tenant_id1',
                        'name': 'tenant_name1',
                    },
                },
                'user': {
                    'id': 'user_id1',
                    'name': 'user_name1',
                    'roles': [
                        {'name': 'role1'},
                        {'name': 'role2'},
                    ],
                },
                'serviceCatalog': {}
            },
        }

        return v2_fixture

    def create_v3_token_fixture(self, expires=None):

        v3_fixture = {
            'token': {
                'expires_at': expires or self.one_hour_earlier,
                'user': {
                    'id': 'user_id1',
                    'name': 'user_name1',
                    'domain': {
                        'id': 'domain_id1',
                        'name': 'domain_name1'
                    }
                },
                'project': {
                    'id': 'tenant_id1',
                    'name': 'tenant_name1',
                    'domain': {
                        'id': 'domain_id1',
                        'name': 'domain_name1'
                    }
                },
                'roles': [
                    {'name': 'role1', 'id': 'Role1'},
                    {'name': 'role2', 'id': 'Role2'},
                ],
                'catalog': {}
            }
        }

        return v3_fixture

    def test_no_data(self):
        data = {}
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._get_token_expiration,
                          data)

    def test_bad_data(self):
        data = {'my_happy_token_dict': 'woo'}
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._get_token_expiration,
                          data)

    def test_v2_token_get_token_expiration_return_isotime(self):
        data = self.create_v2_token_fixture()
        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(self.one_hour_earlier, actual_expires)

    def test_v2_token_not_expired(self):
        data = self.create_v2_token_fixture()
        expected_expires = data['access']['token']['expires']
        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(actual_expires, expected_expires)

    def test_v2_token_expired(self):
        data = self.create_v2_token_fixture(expires=self.one_hour_ago)
        expires = auth_token._get_token_expiration(data)
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._confirm_token_not_expired,
                          expires)

    def test_v2_token_with_timezone_offset_not_expired(self):
        self.useFixture(TimeFixture('2000-01-01T00:01:10.000123Z'))
        data = self.create_v2_token_fixture(
            expires='2000-01-01T05:05:10.000123Z')
        expected_expires = '2000-01-01T05:05:10.000123Z'
        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(actual_expires, expected_expires)

    def test_v2_token_with_timezone_offset_expired(self):
        self.useFixture(TimeFixture('2000-01-01T00:01:10.000123Z'))
        data = self.create_v2_token_fixture(
            expires='1999-12-31T19:05:10Z')
        expires = auth_token._get_token_expiration(data)
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._confirm_token_not_expired,
                          expires)

    def test_v3_token_get_token_expiration_return_isotime(self):
        data = self.create_v3_token_fixture()
        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(self.one_hour_earlier, actual_expires)

    def test_v3_token_not_expired(self):
        data = self.create_v3_token_fixture()
        expected_expires = data['token']['expires_at']
        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(actual_expires, expected_expires)

    def test_v3_token_expired(self):
        data = self.create_v3_token_fixture(expires=self.one_hour_ago)
        expires = auth_token._get_token_expiration(data)
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._confirm_token_not_expired,
                          expires)

    def test_v3_token_with_timezone_offset_not_expired(self):
        self.useFixture(TimeFixture('2000-01-01T00:01:10.000123Z'))
        data = self.create_v3_token_fixture(
            expires='2000-01-01T05:05:10.000123Z')
        expected_expires = '2000-01-01T05:05:10.000123Z'

        actual_expires = auth_token._get_token_expiration(data)
        self.assertEqual(actual_expires, expected_expires)

    def test_v3_token_with_timezone_offset_expired(self):
        self.useFixture(TimeFixture('2000-01-01T00:01:10.000123Z'))
        data = self.create_v3_token_fixture(
            expires='1999-12-31T19:05:10Z')
        expires = auth_token._get_token_expiration(data)
        self.assertRaises(auth_token.InvalidToken,
                          auth_token._confirm_token_not_expired,
                          expires)

    def test_cached_token_not_expired(self):
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        self.middleware._token_cache.initialize({})
        some_time_later = timeutils.strtime(at=(self.now + self.delta))
        expires = some_time_later
        self.middleware._token_cache.store(token, data, expires)
        self.assertEqual(self.middleware._token_cache._cache_get(token), data)

    def test_cached_token_not_expired_with_old_style_nix_timestamp(self):
        """Ensure we cannot retrieve a token from the cache.

        Getting a token from the cache should return None when the token data
        in the cache stores the expires time as a \*nix style timestamp.

        """
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        token_cache = self.middleware._token_cache
        token_cache.initialize({})
        some_time_later = self.now + self.delta
        # Store a unix timestamp in the cache.
        expires = calendar.timegm(some_time_later.timetuple())
        token_cache.store(token, data, expires)
        self.assertIsNone(token_cache._cache_get(token))

    def test_cached_token_expired(self):
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        self.middleware._token_cache.initialize({})
        some_time_earlier = timeutils.strtime(at=(self.now - self.delta))
        expires = some_time_earlier
        self.middleware._token_cache.store(token, data, expires)
        self.assertThat(lambda: self.middleware._token_cache._cache_get(token),
                        matchers.raises(auth_token.InvalidToken))

    def test_cached_token_with_timezone_offset_not_expired(self):
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        self.middleware._token_cache.initialize({})
        timezone_offset = datetime.timedelta(hours=2)
        some_time_later = self.now - timezone_offset + self.delta
        expires = timeutils.strtime(some_time_later) + '-02:00'
        self.middleware._token_cache.store(token, data, expires)
        self.assertEqual(self.middleware._token_cache._cache_get(token), data)

    def test_cached_token_with_timezone_offset_expired(self):
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        self.middleware._token_cache.initialize({})
        timezone_offset = datetime.timedelta(hours=2)
        some_time_earlier = self.now - timezone_offset - self.delta
        expires = timeutils.strtime(some_time_earlier) + '-02:00'
        self.middleware._token_cache.store(token, data, expires)
        self.assertThat(lambda: self.middleware._token_cache._cache_get(token),
                        matchers.raises(auth_token.InvalidToken))


class CatalogConversionTests(BaseAuthTokenMiddlewareTest):

    PUBLIC_URL = 'http://server:5000/v2.0'
    ADMIN_URL = 'http://admin:35357/v2.0'
    INTERNAL_URL = 'http://internal:5000/v2.0'

    REGION_ONE = 'RegionOne'
    REGION_TWO = 'RegionTwo'
    REGION_THREE = 'RegionThree'

    def test_basic_convert(self):
        token = fixture.V3Token()
        s = token.add_service(type='identity')
        s.add_standard_endpoints(public=self.PUBLIC_URL,
                                 admin=self.ADMIN_URL,
                                 internal=self.INTERNAL_URL,
                                 region=self.REGION_ONE)

        auth_ref = access.AccessInfo.factory(body=token)
        catalog_data = auth_ref.service_catalog.get_data()
        catalog = auth_token._v3_to_v2_catalog(catalog_data)

        self.assertEqual(1, len(catalog))
        service = catalog[0]
        self.assertEqual(1, len(service['endpoints']))
        endpoints = service['endpoints'][0]

        self.assertEqual('identity', service['type'])
        self.assertEqual(4, len(endpoints))
        self.assertEqual(self.PUBLIC_URL, endpoints['publicURL'])
        self.assertEqual(self.ADMIN_URL, endpoints['adminURL'])
        self.assertEqual(self.INTERNAL_URL, endpoints['internalURL'])
        self.assertEqual(self.REGION_ONE, endpoints['region'])

    def test_multi_region(self):
        token = fixture.V3Token()
        s = token.add_service(type='identity')

        s.add_endpoint('internal', self.INTERNAL_URL, region=self.REGION_ONE)
        s.add_endpoint('public', self.PUBLIC_URL, region=self.REGION_TWO)
        s.add_endpoint('admin', self.ADMIN_URL, region=self.REGION_THREE)

        auth_ref = access.AccessInfo.factory(body=token)
        catalog_data = auth_ref.service_catalog.get_data()
        catalog = auth_token._v3_to_v2_catalog(catalog_data)

        self.assertEqual(1, len(catalog))
        service = catalog[0]

        # the 3 regions will come through as 3 separate endpoints
        expected = [{'internalURL': self.INTERNAL_URL,
                    'region': self.REGION_ONE},
                    {'publicURL': self.PUBLIC_URL,
                     'region': self.REGION_TWO},
                    {'adminURL': self.ADMIN_URL,
                     'region': self.REGION_THREE}]

        self.assertEqual('identity', service['type'])
        self.assertEqual(3, len(service['endpoints']))
        for e in expected:
            self.assertIn(e, expected)


class DelayedAuthTests(BaseAuthTokenMiddlewareTest):

    def test_header_in_401(self):
        body = uuid.uuid4().hex
        auth_uri = 'http://local.test'
        conf = {'delay_auth_decision': 'True',
                'auth_version': 'v3.0',
                'auth_uri': auth_uri}

        self.fake_app = new_app('401 Unauthorized', body)
        self.set_middleware(conf=conf)

        req = webob.Request.blank('/')
        resp = self.middleware(req.environ, self.start_fake_response)

        self.assertEqual([six.b(body)], resp)

        self.assertEqual(401, self.response_status)
        self.assertEqual("Keystone uri='%s'" % auth_uri,
                         self.response_headers['WWW-Authenticate'])

    def test_delayed_auth_values(self):
        fake_app = new_app('401 Unauthorized', uuid.uuid4().hex)
        middleware = auth_token.AuthProtocol(fake_app,
                                             {'auth_uri': 'http://local.test'})
        self.assertFalse(middleware._delay_auth_decision)

        for v in ('True', '1', 'on', 'yes'):
            conf = {'delay_auth_decision': v,
                    'auth_uri': 'http://local.test'}

            middleware = auth_token.AuthProtocol(fake_app, conf)
            self.assertTrue(middleware._delay_auth_decision)

        for v in ('False', '0', 'no'):
            conf = {'delay_auth_decision': v,
                    'auth_uri': 'http://local.test'}

            middleware = auth_token.AuthProtocol(fake_app, conf)
            self.assertFalse(middleware._delay_auth_decision)

    def test_auth_plugin_with_no_tokens(self):
        body = uuid.uuid4().hex
        auth_uri = 'http://local.test'
        conf = {'delay_auth_decision': True, 'auth_uri': auth_uri}
        self.fake_app = new_app('200 OK', body)
        self.set_middleware(conf=conf)

        req = webob.Request.blank('/')
        resp = self.middleware(req.environ, self.start_fake_response)

        self.assertEqual([six.b(body)], resp)

        token_auth = req.environ['keystone.token_auth']

        self.assertFalse(token_auth.has_user_token)
        self.assertIsNone(token_auth.user)
        self.assertFalse(token_auth.has_service_token)
        self.assertIsNone(token_auth.service)


class CommonCompositeAuthTests(object):
    """Test Composite authentication.

    Test the behaviour of adding a service-token.
    """

    def test_composite_auth_ok(self):
        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        fake_logger = fixtures.FakeLogger(level=logging.DEBUG)
        self.middleware.logger = self.useFixture(fake_logger)
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)
        self.assertEqual([FakeApp.SUCCESS], body)
        expected_env = dict(EXPECTED_V2_DEFAULT_ENV_RESPONSE)
        expected_env.update(EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE)
        self.assertIn('Received request from user: '
                      'user_id %(HTTP_X_USER_ID)s, '
                      'project_id %(HTTP_X_TENANT_ID)s, '
                      'roles %(HTTP_X_ROLES)s '
                      'service: user_id %(HTTP_X_SERVICE_USER_ID)s, '
                      'project_id %(HTTP_X_SERVICE_PROJECT_ID)s, '
                      'roles %(HTTP_X_SERVICE_ROLES)s' % expected_env,
                      fake_logger.output)

    def test_composite_auth_invalid_service_token(self):
        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        service_token = 'invalid-service-token'
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual([b'Authentication required'], body)

    def test_composite_auth_no_service_token(self):
        self.purge_service_token_expected_env()
        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        req.headers['X-Auth-Token'] = token

        # Ensure injection of service headers is not possible
        for key, value in six.iteritems(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            req.headers[header_key] = value
        # Check arbitrary headers not removed
        req.headers['X-Foo'] = 'Bar'
        body = self.middleware(req.environ, self.start_fake_response)
        for key in six.iterkeys(self.service_token_expected_env):
            self.assertFalse(req.headers.get(key))
        self.assertEqual('Bar', req.headers.get('X-Foo'))
        self.assertEqual(418, self.response_status)
        self.assertEqual([FakeApp.FORBIDDEN], body)

    def test_composite_auth_invalid_user_token(self):
        req = webob.Request.blank('/')
        token = 'invalid-token'
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual([b'Authentication required'], body)

    def test_composite_auth_no_user_token(self):
        req = webob.Request.blank('/')
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual([b'Authentication required'], body)

    def test_composite_auth_delay_ok(self):
        self.middleware._delay_auth_decision = True
        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(200, self.response_status)
        self.assertEqual([FakeApp.SUCCESS], body)

    def test_composite_auth_delay_invalid_service_token(self):
        self.middleware._delay_auth_decision = True
        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        service_token = 'invalid-service-token'
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(401, self.response_status)
        self.assertEqual([b'Authentication required'], body)

    def test_composite_auth_delay_no_service_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_service_token_expected_env()

        req = webob.Request.blank('/')
        token = self.token_dict['uuid_token_default']
        req.headers['X-Auth-Token'] = token

        # Ensure injection of service headers is not possible
        for key, value in six.iteritems(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            req.headers[header_key] = value
        # Check arbitrary headers not removed
        req.headers['X-Foo'] = 'Bar'
        body = self.middleware(req.environ, self.start_fake_response)
        for key in six.iterkeys(self.service_token_expected_env):
            self.assertFalse(req.headers.get(key))
        self.assertEqual('Bar', req.headers.get('X-Foo'))
        self.assertEqual(418, self.response_status)
        self.assertEqual([FakeApp.FORBIDDEN], body)

    def test_composite_auth_delay_invalid_user_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_token_expected_env()
        expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        req = webob.Request.blank('/')
        token = 'invalid-token'
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Auth-Token'] = token
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(403, self.response_status)
        self.assertEqual([FakeApp.FORBIDDEN], body)

    def test_composite_auth_delay_no_user_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_token_expected_env()
        expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        req = webob.Request.blank('/')
        service_token = self.token_dict['uuid_service_token_default']
        req.headers['X-Service-Token'] = service_token
        body = self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(403, self.response_status)
        self.assertEqual([FakeApp.FORBIDDEN], body)


class v2CompositeAuthTests(BaseAuthTokenMiddlewareTest,
                           CommonCompositeAuthTests,
                           testresources.ResourcedTestCase):
    """Test auth_token middleware with v2 token based composite auth.

    Execute the Composite auth class tests, but with the
    auth_token middleware configured to expect v2 tokens back from
    a keystone server.
    """

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(v2CompositeAuthTests, self).setUp(
            expected_env=EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE,
            fake_app=CompositeFakeApp)

        uuid_token_default = self.examples.UUID_TOKEN_DEFAULT
        uuid_service_token_default = self.examples.UUID_SERVICE_TOKEN_DEFAULT
        self.token_dict = {
            'uuid_token_default': uuid_token_default,
            'uuid_service_token_default': uuid_service_token_default,
        }

        self.requests.get(BASE_URI,
                          json=VERSION_LIST_v2,
                          status_code=300)

        self.requests.post('%s/v2.0/tokens' % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        self.requests.get('%s/v2.0/tokens/revoked' % BASE_URI,
                          text=self.examples.SIGNED_REVOCATION_LIST,
                          status_code=200)

        for token in (self.examples.UUID_TOKEN_DEFAULT,
                      self.examples.UUID_SERVICE_TOKEN_DEFAULT,):
            self.requests.get('%s/v2.0/tokens/%s' % (BASE_URI, token),
                              text=self.examples.JSON_TOKEN_RESPONSES[token])

        for invalid_uri in ("%s/v2.0/tokens/invalid-token" % BASE_URI,
                            "%s/v2.0/tokens/invalid-service-token" % BASE_URI):
            self.requests.get(invalid_uri, text='', status_code=404)

        self.token_expected_env = dict(EXPECTED_V2_DEFAULT_ENV_RESPONSE)
        self.service_token_expected_env = dict(
            EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE)
        self.set_middleware()


class v3CompositeAuthTests(BaseAuthTokenMiddlewareTest,
                           CommonCompositeAuthTests,
                           testresources.ResourcedTestCase):
    """Test auth_token middleware with v3 token based composite auth.

    Execute the Composite auth class tests, but with the
    auth_token middleware configured to expect v3 tokens back from
    a keystone server.
    """

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(v3CompositeAuthTests, self).setUp(
            auth_version='v3.0',
            fake_app=v3CompositeFakeApp)

        uuid_token_default = self.examples.v3_UUID_TOKEN_DEFAULT
        uuid_serv_token_default = self.examples.v3_UUID_SERVICE_TOKEN_DEFAULT
        self.token_dict = {
            'uuid_token_default': uuid_token_default,
            'uuid_service_token_default': uuid_serv_token_default,
        }

        self.requests.get(BASE_URI, json=VERSION_LIST_v3, status_code=300)

        # TODO(jamielennox): auth_token middleware uses a v2 admin token
        # regardless of the auth_version that is set.
        self.requests.post('%s/v2.0/tokens' % BASE_URI,
                           text=FAKE_ADMIN_TOKEN)

        # TODO(jamielennox): there is no v3 revocation url yet, it uses v2
        self.requests.get('%s/v2.0/tokens/revoked' % BASE_URI,
                          text=self.examples.SIGNED_REVOCATION_LIST)

        self.requests.get('%s/v3/auth/tokens' % BASE_URI,
                          text=self.token_response)

        self.token_expected_env = dict(EXPECTED_V2_DEFAULT_ENV_RESPONSE)
        self.token_expected_env.update(EXPECTED_V3_DEFAULT_ENV_ADDITIONS)
        self.service_token_expected_env = dict(
            EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE)
        self.service_token_expected_env.update(
            EXPECTED_V3_DEFAULT_SERVICE_ENV_ADDITIONS)
        self.set_middleware()

    def token_response(self, request, context):
        auth_id = request.headers.get('X-Auth-Token')
        token_id = request.headers.get('X-Subject-Token')
        self.assertEqual(auth_id, FAKE_ADMIN_TOKEN_ID)

        status = 200
        response = ""

        if token_id == ERROR_TOKEN:
            raise exceptions.ConnectionError("Network connection error.")

        try:
            response = self.examples.JSON_TOKEN_RESPONSES[token_id]
        except KeyError:
            status = 404

        context.status_code = status
        return response


class OtherTests(BaseAuthTokenMiddlewareTest):

    def setUp(self):
        super(OtherTests, self).setUp()
        self.logger = self.useFixture(fixtures.FakeLogger())

    def test_unknown_server_versions(self):
        versions = fixture.DiscoveryList(v2=False, v3_id='v4', href=BASE_URI)
        self.set_middleware()

        self.requests.get(BASE_URI, json=versions, status_code=300)

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = uuid.uuid4().hex
        self.middleware(req.environ, self.start_fake_response)
        self.assertEqual(503, self.response_status)

        self.assertIn('versions [v3.0, v2.0]', self.logger.output)

    def _assert_auth_version(self, conf_version, identity_server_version):
        self.set_middleware(conf={'auth_version': conf_version})
        identity_server = self.middleware._create_identity_server()
        self.assertEqual(identity_server_version,
                         identity_server.auth_version)

    def test_micro_version(self):
        self._assert_auth_version('v2', (2, 0))
        self._assert_auth_version('v2.0', (2, 0))
        self._assert_auth_version('v3', (3, 0))
        self._assert_auth_version('v3.0', (3, 0))
        self._assert_auth_version('v3.1', (3, 0))
        self._assert_auth_version('v3.2', (3, 0))
        self._assert_auth_version('v3.9', (3, 0))
        self._assert_auth_version('v3.3.1', (3, 0))
        self._assert_auth_version('v3.3.5', (3, 0))

    def test_default_auth_version(self):
        # VERSION_LIST_v3 contains both v2 and v3 version elements
        self.requests.get(BASE_URI, json=VERSION_LIST_v3, status_code=300)
        self._assert_auth_version(None, (3, 0))

        # VERSION_LIST_v2 contains only v2 version elements
        self.requests.get(BASE_URI, json=VERSION_LIST_v2, status_code=300)
        self._assert_auth_version(None, (2, 0))

    def test_unsupported_auth_version(self):
        # If the requested version isn't supported we will use v2
        self._assert_auth_version('v1', (2, 0))
        self._assert_auth_version('v10', (2, 0))


class DefaultAuthPluginTests(testtools.TestCase):

    def new_plugin(self, auth_host=None, auth_port=None, auth_protocol=None,
                   auth_admin_prefix=None, admin_user=None,
                   admin_password=None, admin_tenant_name=None,
                   admin_token=None, identity_uri=None, log=None):
        if not log:
            log = self.logger

        return auth_token._AuthTokenPlugin.load_from_options(
            auth_host=auth_host,
            auth_port=auth_port,
            auth_protocol=auth_protocol,
            auth_admin_prefix=auth_admin_prefix,
            admin_user=admin_user,
            admin_password=admin_password,
            admin_tenant_name=admin_tenant_name,
            admin_token=admin_token,
            identity_uri=identity_uri,
            log=log)

    def setUp(self):
        super(DefaultAuthPluginTests, self).setUp()

        self.stream = six.StringIO()
        self.logger = logging.getLogger(__name__)
        self.session = session.Session()
        self.requests = self.useFixture(rm_fixture.Fixture())

    def test_auth_uri_from_fragments(self):
        auth_protocol = 'http'
        auth_host = 'testhost'
        auth_port = 8888
        auth_admin_prefix = 'admin'

        expected = '%s://%s:%d/admin' % (auth_protocol, auth_host, auth_port)

        plugin = self.new_plugin(auth_host=auth_host,
                                 auth_protocol=auth_protocol,
                                 auth_port=auth_port,
                                 auth_admin_prefix=auth_admin_prefix)

        self.assertEqual(expected,
                         plugin.get_endpoint(self.session,
                                             interface=auth.AUTH_INTERFACE))

    def test_identity_uri_overrides_fragments(self):
        identity_uri = 'http://testhost:8888/admin'
        plugin = self.new_plugin(identity_uri=identity_uri,
                                 auth_host='anotherhost',
                                 auth_port=9999,
                                 auth_protocol='ftp')

        self.assertEqual(identity_uri,
                         plugin.get_endpoint(self.session,
                                             interface=auth.AUTH_INTERFACE))

    def test_with_admin_token(self):
        token = uuid.uuid4().hex
        plugin = self.new_plugin(identity_uri='http://testhost:8888/admin',
                                 admin_token=token)
        self.assertEqual(token, plugin.get_token(self.session))

    def test_with_user_pass(self):
        base_uri = 'http://testhost:8888/admin'
        token = fixture.V2Token()
        admin_tenant_name = uuid.uuid4().hex

        self.requests.post(base_uri + '/v2.0/tokens',
                           json=token)

        plugin = self.new_plugin(identity_uri=base_uri,
                                 admin_user=uuid.uuid4().hex,
                                 admin_password=uuid.uuid4().hex,
                                 admin_tenant_name=admin_tenant_name)

        self.assertEqual(token.token_id, plugin.get_token(self.session))


class AuthProtocolLoadingTests(BaseAuthTokenMiddlewareTest):

    AUTH_URL = 'http://auth.url/prefix'
    DISC_URL = 'http://disc.url/prefix'
    KEYSTONE_BASE_URL = 'http://keystone.url/prefix'
    CRUD_URL = 'http://crud.url/prefix'

    # NOTE(jamielennox): use the /v2.0 prefix here because this is what's most
    # likely to be in the service catalog and we should be able to ignore it.
    KEYSTONE_URL = KEYSTONE_BASE_URL + '/v2.0'

    def setUp(self):
        super(AuthProtocolLoadingTests, self).setUp()
        self.cfg = self.useFixture(cfg_fixture.Config())

    def test_loading_password_plugin(self):
        # the password options aren't set on config until loading time, but we
        # need them set so we can override the values for testing, so force it
        opts = auth.get_plugin_options('password')
        self.cfg.register_opts(opts, group=auth_token._AUTHTOKEN_GROUP)

        project_id = uuid.uuid4().hex

        # configure the authentication options
        self.cfg.config(auth_plugin='password',
                        username='testuser',
                        password='testpass',
                        auth_url=self.AUTH_URL,
                        project_id=project_id,
                        user_domain_id='userdomainid',
                        group=auth_token._AUTHTOKEN_GROUP)

        # admin_token is the token that the service will get back from auth
        admin_token_id = uuid.uuid4().hex
        admin_token = fixture.V3Token(project_id=project_id)
        s = admin_token.add_service('identity', name='keystone')
        s.add_standard_endpoints(admin=self.KEYSTONE_URL)

        # user_token is the data from the user's inputted token
        user_token_id = uuid.uuid4().hex
        user_token = fixture.V3Token()
        user_token.set_project_scope()

        # first touch is to discover the available versions at the auth_url
        self.requests.get(self.AUTH_URL,
                          json=fixture.DiscoveryList(href=self.DISC_URL),
                          status_code=300)

        # then we use the url returned from discovery to actually auth
        self.requests.post(self.DISC_URL + '/v3/auth/tokens',
                           json=admin_token,
                           headers={'X-Subject-Token': admin_token_id})

        # then we do discovery on the URL from the service catalog. In practice
        # this is mostly the same URL as before but test the full range.
        self.requests.get(self.KEYSTONE_BASE_URL + '/',
                          json=fixture.DiscoveryList(href=self.CRUD_URL),
                          status_code=300)

        # actually authenticating the user will then use the base url that was
        # retrieved from discovery from the service catalog.
        self.requests.get(self.CRUD_URL + '/v3/auth/tokens',
                          request_headers={'X-Subject-Token': user_token_id,
                                           'X-Auth-Token': admin_token_id},
                          json=user_token)

        body = uuid.uuid4().hex
        app = auth_token.AuthProtocol(new_app('200 OK', body)(), {})

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = user_token_id
        resp = app(req.environ, self.start_fake_response)

        self.assertEqual(200, self.response_status)
        self.assertEqual(six.b(body), resp[0])

    def test_invalid_plugin_fails_to_intialize(self):
        self.cfg.config(auth_plugin=uuid.uuid4().hex,
                        group=auth_token._AUTHTOKEN_GROUP)

        self.assertRaises(
            exceptions.NoMatchingPlugin,
            lambda: auth_token.AuthProtocol(new_app('200 OK', '')(), {}))


def load_tests(loader, tests, pattern):
    return testresources.OptimisingTestSuite(tests)
