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

import datetime
import logging
import os
import pkg_resources
import shutil
import stat
import tempfile
import time
import uuid

import fixtures
from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import fixture
from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneclient.common import cms
from keystoneclient import exceptions as ksc_exceptions
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from oslotest import createfile
import six
import testresources
import testtools
from testtools import matchers
import webob
import webob.dec

from keystonemiddleware import auth_token
from keystonemiddleware.auth_token import _base
from keystonemiddleware.auth_token import _exceptions as ksm_exceptions
from keystonemiddleware.auth_token import _revocations
from keystonemiddleware.openstack.common import memorycache
from keystonemiddleware.tests.unit.auth_token import base
from keystonemiddleware.tests.unit import client_fixtures


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
    'HTTP_X_SERVICE_IDENTITY_STATUS': 'Confirmed',
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


def cleanup_revoked_file(filename):
    try:
        os.remove(filename)
    except OSError:
        pass


def strtime(at=None):
    at = at or timeutils.utcnow()
    return at.strftime(timeutils.PERFECT_TIME_FORMAT)


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

    @webob.dec.wsgify
    def __call__(self, req):
        for k, v in self.expected_env.items():
            assert req.environ[k] == v, '%s != %s' % (req.environ[k], v)

        resp = webob.Response()

        if (req.environ.get('HTTP_X_IDENTITY_STATUS') == 'Invalid' and
                req.environ['HTTP_X_SERVICE_IDENTITY_STATUS'] == 'Invalid'):
            # Simulate delayed auth forbidding access with arbitrary status
            # code to differentiate checking this code path
            resp.status = 419
            resp.body = FakeApp.FORBIDDEN
        elif req.environ.get('HTTP_X_SERVICE_IDENTITY_STATUS') == 'Invalid':
            # Simulate delayed auth forbidding access with arbitrary status
            # code to differentiate checking this code path
            resp.status = 420
            resp.body = FakeApp.FORBIDDEN
        elif req.environ['HTTP_X_IDENTITY_STATUS'] == 'Invalid':
            # Simulate delayed auth forbidding access
            resp.status = 403
            resp.body = FakeApp.FORBIDDEN
        elif (self.need_service_token is True and
              req.environ.get('HTTP_X_SERVICE_TOKEN') is None):
            # Simulate requiring composite auth
            # Arbitrary value to allow checking this code path
            resp.status = 418
            resp.body = FakeApp.FORBIDDEN
        else:
            resp.body = FakeApp.SUCCESS

        return resp


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


class BaseAuthTokenMiddlewareTest(base.BaseAuthTokenTestCase):
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

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        self.expected_env = expected_env or dict()
        self.fake_app = fake_app or FakeApp
        self.middleware = None

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

    def call_middleware(self, **kwargs):
        return self.call(self.middleware, **kwargs)

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

        self.middleware._revocations._list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})

    def update_expected_env(self, expected_env={}):
        self.middleware._app.expected_env.update(expected_env)

    def purge_token_expected_env(self):
        for key in six.iterkeys(self.token_expected_env):
            del self.middleware._app.expected_env[key]

    def purge_service_token_expected_env(self):
        for key in six.iterkeys(self.service_token_expected_env):
            del self.middleware._app.expected_env[key]

    def assertLastPath(self, path):
        if path:
            self.assertEqual(BASE_URI + path,
                             self.requests_mock.last_request.url)
        else:
            self.assertIsNone(self.requests_mock.last_request)


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

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v2,
                               status_code=300)

        self.requests_mock.post("%s/v2.0/tokens" % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        self.token_id = self.examples.VALID_DIABLO_TOKEN
        token_response = self.examples.JSON_TOKEN_RESPONSES[self.token_id]

        url = "%s/v2.0/tokens/%s" % (BASE_URI, self.token_id)
        self.requests_mock.get(url, text=token_response)

        self.set_middleware()

    def test_valid_diablo_response(self):
        resp = self.call_middleware(headers={'X-Auth-Token': self.token_id})
        self.assertIn('keystone.token_info', resp.request.environ)


class CachePoolTest(BaseAuthTokenMiddlewareTest):
    def test_use_cache_from_env(self):
        # If `swift.cache` is set in the environment and `cache` is set in the
        # config then the env cache is used.
        env = {'swift.cache': 'CACHE_TEST'}
        conf = {
            'cache': 'swift.cache'
        }
        self.set_middleware(conf=conf)
        self.middleware._token_cache.initialize(env)
        with self.middleware._token_cache._cache_pool.reserve() as cache:
            self.assertEqual(cache, 'CACHE_TEST')

    def test_not_use_cache_from_env(self):
        # If `swift.cache` is set in the environment but `cache` isn't set
        # initialize the config then the env cache isn't used.
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
    """General Token Behavior tests.

    These tests are not affected by the token format
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

    def test_fixed_cache_key_length(self):
        self.set_middleware()
        short_string = uuid.uuid4().hex
        long_string = 8 * uuid.uuid4().hex

        token_cache = self.middleware._token_cache
        hashed_short_string_key, context_ = token_cache._get_cache_key(
            short_string)
        hashed_long_string_key, context_ = token_cache._get_cache_key(
            long_string)

        # The hash keys should always match in length
        self.assertThat(hashed_short_string_key,
                        matchers.HasLength(len(hashed_long_string_key)))

    def test_config_revocation_cache_timeout(self):
        conf = {
            'revocation_cache_time': '24',
            'auth_uri': 'https://keystone.example.com:1234',
            'admin_user': uuid.uuid4().hex
        }
        middleware = auth_token.AuthProtocol(self.fake_app, conf)
        self.assertEqual(middleware._revocations._cache_timeout,
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
                         middleware._revocations._cache_timeout)
        self.assertEqual(False, middleware._include_service_catalog)
        self.assertEqual('0', middleware._conf['nonexsit_option'])

    def test_deprecated_conf_values(self):
        servers = 'localhost:11211'

        conf = {
            'memcache_servers': servers
        }

        middleware = auth_token.AuthProtocol(self.fake_app, conf)
        self.assertEqual([servers], middleware._conf_get('memcached_servers'))

    def test_conf_values_type_convert_with_wrong_value(self):
        conf = {
            'include_service_catalog': '123',
        }
        self.assertRaises(ksm_exceptions.ConfigurationError,
                          auth_token.AuthProtocol, self.fake_app, conf)

    def test_auth_region_name(self):
        token = fixture.V3Token()

        auth_url = 'http://keystone-auth.example.com:5000'
        east_url = 'http://keystone-east.example.com:5000'
        west_url = 'http://keystone-west.example.com:5000'

        auth_versions = fixture.DiscoveryList(href=auth_url)
        east_versions = fixture.DiscoveryList(href=east_url)
        west_versions = fixture.DiscoveryList(href=west_url)

        s = token.add_service('identity')
        s.add_endpoint(interface='admin', url=east_url, region='east')
        s.add_endpoint(interface='admin', url=west_url, region='west')

        self.requests_mock.get(auth_url, json=auth_versions)
        self.requests_mock.get(east_url, json=east_versions)
        self.requests_mock.get(west_url, json=west_versions)

        self.requests_mock.post(
            '%s/v3/auth/tokens' % auth_url,
            headers={'X-Subject-Token': uuid.uuid4().hex},
            json=token)

        east_mock = self.requests_mock.get(
            '%s/v3/auth/tokens' % east_url,
            headers={'X-Subject-Token': uuid.uuid4().hex},
            json=fixture.V3Token())

        west_mock = self.requests_mock.get(
            '%s/v3/auth/tokens' % west_url,
            headers={'X-Subject-Token': uuid.uuid4().hex},
            json=fixture.V3Token())

        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)

        opts = loading.get_auth_plugin_conf_options('v3password')
        self.cfg.register_opts(opts, group=_base.AUTHTOKEN_GROUP)

        self.cfg.config(auth_url=auth_url + '/v3',
                        auth_type='v3password',
                        username='user',
                        password='pass',
                        user_domain_id=uuid.uuid4().hex,
                        group=_base.AUTHTOKEN_GROUP)

        self.assertEqual(0, east_mock.call_count)
        self.assertEqual(0, west_mock.call_count)

        east_app = self.create_simple_middleware(conf=dict(region_name='east'))
        self.call(east_app, headers={'X-Auth-Token': uuid.uuid4().hex})

        self.assertEqual(1, east_mock.call_count)
        self.assertEqual(0, west_mock.call_count)

        west_app = self.create_simple_middleware(conf=dict(region_name='west'))

        self.call(west_app, headers={'X-Auth-Token': uuid.uuid4().hex})

        self.assertEqual(1, east_mock.call_count)
        self.assertEqual(1, west_mock.call_count)


class CommonAuthTokenMiddlewareTest(object):
    """These tests are run once using v2 tokens and again using v3 tokens."""

    def test_init_does_not_call_http(self):
        conf = {
            'revocation_cache_time': '1'
        }
        self.create_simple_middleware(conf=conf)
        self.assertLastPath(None)

    def test_auth_with_no_token_does_not_call_http(self):
        middleware = self.create_simple_middleware()
        self.call(middleware, expected_status=401)
        self.assertLastPath(None)

    def test_init_by_ipv6Addr_auth_host(self):
        del self.conf['identity_uri']
        conf = {
            'auth_host': '2001:2013:1:f101::1',
            'auth_port': '1234',
            'auth_protocol': 'http',
            'auth_uri': None,
            'auth_version': 'v3.0',
        }
        middleware = self.create_simple_middleware(conf=conf)
        self.assertEqual('http://[2001:2013:1:f101::1]:1234',
                         middleware._auth_uri)

    def assert_valid_request_200(self, token, with_catalog=True):
        resp = self.call_middleware(headers={'X-Auth-Token': token})
        if with_catalog:
            self.assertTrue(resp.request.headers.get('X-Service-Catalog'))
        else:
            self.assertNotIn('X-Service-Catalog', resp.request.headers)
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertIn('keystone.token_info', resp.request.environ)
        return resp.request

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

        # Token should be cached as ok after this.
        self.call_middleware(headers={'X-Auth-Token': token})

        # Put it in revocation list.
        self.middleware._revocations._list = self.get_revocation_list_json(
            token_ids=[revoked_form or token])

        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

    def test_cached_revoked_error(self):
        # When the token is cached and revocation list retrieval fails,
        # 503 is returned
        token = self.token_dict['uuid_token_default']
        self.middleware._check_revocations_for_cached = True

        # Token should be cached as ok after this.
        resp = self.call_middleware(headers={'X-Auth-Token': token})
        self.assertEqual(200, resp.status_int)

        # Cause the revocation list to be fetched again next time so we can
        # test the case where that retrieval fails
        self.middleware._revocations._fetched_time = datetime.datetime.min
        with mock.patch.object(self.middleware._revocations, '_fetch',
                               side_effect=ksm_exceptions.RevocationListError):
            self.call_middleware(headers={'X-Auth-Token': token},
                                 expected_status=503)

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
        self.middleware._revocations._list = (
            self.get_revocation_list_json())

        token = self.token_dict['revoked_token']
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

    def test_revoked_token_receives_401_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._revocations._list = (
            self.get_revocation_list_json(mode='sha256'))

        token = self.token_dict['revoked_token']
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

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
        self.middleware._revocations._list = (
            self.get_revocation_list_json())

        token = self.token_dict['revoked_token']
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

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
        self.middleware._revocations._list = self.get_revocation_list_json(
            token_ids=[token_hashed])

        # First, request is using the hashed token, is valid so goes in
        # cache using the given hash.
        self.call_middleware(headers={'X-Auth-Token': token_hashed})

        # This time use the PKI(Z) token
        # Should find the token in the cache and revocation list.
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

    def test_revoked_hashed_pki_token(self):
        self._test_revoked_hashed_token('signed_token_scoped')

    def test_revoked_hashed_pkiz_token(self):
        self._test_revoked_hashed_token('signed_token_scoped_pkiz')

    def test_revoked_pki_token_by_audit_id(self):
        # When the audit ID is in the revocation list, the token is invalid.
        self.set_middleware()
        token = self.token_dict['signed_token_scoped']

        # Put the token audit ID in the revocation list,
        # the entry will have a false token ID so the token ID doesn't match.
        fake_token_id = uuid.uuid4().hex
        # The audit_id value is in examples/pki/cms/auth_*_token_scoped.json.
        audit_id = 'SLIXlXQUQZWUi9VJrqdXqA'
        revocation_list_data = {
            'revoked': [
                {
                    'id': fake_token_id,
                    'audit_id': audit_id
                },
            ]
        }
        self.middleware._revocations._list = jsonutils.dumps(
            revocation_list_data)

        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

    def get_revocation_list_json(self, token_ids=None, mode=None):
        if token_ids is None:
            key = 'revoked_token_hash' + (('_' + mode) if mode else '')
            token_ids = [self.token_dict[key]]
        revocation_list = {'revoked': [{'id': x, 'expires': timeutils.utcnow()}
                                       for x in token_ids]}
        return jsonutils.dumps(revocation_list)

    def test_is_signed_token_revoked_returns_false(self):
        # explicitly setting an empty revocation list here to document intent
        self.middleware._revocations._list = jsonutils.dumps(
            {"revoked": [], "extra": "success"})
        result = self.middleware._revocations._any_revoked(
            [self.token_dict['revoked_token_hash']])
        self.assertFalse(result)

    def test_is_signed_token_revoked_returns_true(self):
        self.middleware._revocations._list = (
            self.get_revocation_list_json())
        result = self.middleware._revocations._any_revoked(
            [self.token_dict['revoked_token_hash']])
        self.assertTrue(result)

    def test_is_signed_token_revoked_returns_true_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._revocations._list = (
            self.get_revocation_list_json(mode='sha256'))
        result = self.middleware._revocations._any_revoked(
            [self.token_dict['revoked_token_hash_sha256']])
        self.assertTrue(result)

    def test_validate_offline_raises_exception_for_revoked_token(self):
        self.middleware._revocations._list = (
            self.get_revocation_list_json())
        self.assertRaises(ksm_exceptions.InvalidToken,
                          self.middleware._validate_offline,
                          self.token_dict['revoked_token'],
                          [self.token_dict['revoked_token_hash']])

    def test_validate_offline_raises_exception_for_revoked_token_s256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._revocations._list = (
            self.get_revocation_list_json(mode='sha256'))
        self.assertRaises(ksm_exceptions.InvalidToken,
                          self.middleware._validate_offline,
                          self.token_dict['revoked_token'],
                          [self.token_dict['revoked_token_hash_sha256'],
                           self.token_dict['revoked_token_hash']])

    def test_validate_offline_raises_exception_for_revoked_pkiz_token(self):
        self.middleware._revocations._list = (
            self.examples.REVOKED_TOKEN_PKIZ_LIST_JSON)
        self.assertRaises(ksm_exceptions.InvalidToken,
                          self.middleware._validate_offline,
                          self.token_dict['revoked_token_pkiz'],
                          [self.token_dict['revoked_token_pkiz_hash']])

    def test_validate_offline_succeeds_for_unrevoked_token(self):
        self.middleware._revocations._list = (
            self.get_revocation_list_json())
        token = self.middleware._validate_offline(
            self.token_dict['signed_token_scoped'],
            [self.token_dict['signed_token_scoped_hash']])
        self.assertIsInstance(token, dict)

    def test_verify_signed_compressed_token_succeeds_for_unrevoked_token(self):
        self.middleware._revocations._list = (
            self.get_revocation_list_json())
        token = self.middleware._validate_offline(
            self.token_dict['signed_token_scoped_pkiz'],
            [self.token_dict['signed_token_scoped_hash']])
        self.assertIsInstance(token, dict)

    def test_validate_offline_token_succeeds_for_unrevoked_token_sha256(self):
        self.conf['hash_algorithms'] = ','.join(['sha256', 'md5'])
        self.set_middleware()
        self.middleware._revocations._list = (
            self.get_revocation_list_json(mode='sha256'))
        token = self.middleware._validate_offline(
            self.token_dict['signed_token_scoped'],
            [self.token_dict['signed_token_scoped_hash_sha256'],
             self.token_dict['signed_token_scoped_hash']])
        self.assertIsInstance(token, dict)

    def test_get_token_revocation_list_fetched_time_returns_min(self):
        self.middleware._revocations._fetched_time = None

        # Get rid of the revoked file
        revoked_path = self.middleware._signing_directory.calc_path(
            _revocations.Revocations._FILE_NAME)
        os.remove(revoked_path)

        self.assertEqual(self.middleware._revocations._fetched_time,
                         datetime.datetime.min)

    # FIXME(blk-u): move the unit tests into unit/test_auth_token.py
    def test_get_token_revocation_list_fetched_time_returns_mtime(self):
        self.middleware._revocations._fetched_time = None
        revoked_path = self.middleware._signing_directory.calc_path(
            _revocations.Revocations._FILE_NAME)
        mtime = os.path.getmtime(revoked_path)
        fetched_time = datetime.datetime.utcfromtimestamp(mtime)
        self.assertEqual(fetched_time,
                         self.middleware._revocations._fetched_time)

    @testtools.skipUnless(TimezoneFixture.supported(),
                          'TimezoneFixture not supported')
    def test_get_token_revocation_list_fetched_time_returns_utc(self):
        with TimezoneFixture('UTC-1'):
            self.middleware._revocations._list = jsonutils.dumps(
                self.examples.REVOCATION_LIST)
            self.middleware._revocations._fetched_time = None
            fetched_time = self.middleware._revocations._fetched_time
            self.assertTrue(timeutils.is_soon(fetched_time, 1))

    def test_get_token_revocation_list_fetched_time_returns_value(self):
        expected = self.middleware._revocations._fetched_time
        self.assertEqual(self.middleware._revocations._fetched_time,
                         expected)

    def test_get_revocation_list_returns_fetched_list(self):
        # auth_token uses v2 to fetch this, so don't allow the v3
        # tests to override the fake http connection
        self.middleware._revocations._fetched_time = None

        # Get rid of the revoked file
        revoked_path = self.middleware._signing_directory.calc_path(
            _revocations.Revocations._FILE_NAME)
        os.remove(revoked_path)

        self.assertEqual(self.middleware._revocations._list,
                         self.examples.REVOCATION_LIST)

    def test_get_revocation_list_returns_current_list_from_memory(self):
        self.assertEqual(self.middleware._revocations._list,
                         self.middleware._revocations._list_prop)

    def test_get_revocation_list_returns_current_list_from_disk(self):
        in_memory_list = self.middleware._revocations._list
        self.middleware._revocations._list_prop = None
        self.assertEqual(self.middleware._revocations._list,
                         in_memory_list)

    def test_invalid_revocation_list_raises_error(self):
        self.requests_mock.get(self.revocation_url, json={})
        self.assertRaises(ksm_exceptions.RevocationListError,
                          self.middleware._revocations._fetch)

    def test_fetch_revocation_list(self):
        # auth_token uses v2 to fetch this, so don't allow the v3
        # tests to override the fake http connection
        fetched = jsonutils.loads(self.middleware._revocations._fetch())
        self.assertEqual(fetched, self.examples.REVOCATION_LIST)

    def test_request_invalid_uuid_token(self):
        # remember because we are testing the middleware we stub the connection
        # to the keystone server, but this is not what gets returned
        invalid_uri = "%s/v2.0/tokens/invalid-token" % BASE_URI
        self.requests_mock.get(invalid_uri, status_code=404)

        resp = self.call_middleware(headers={'X-Auth-Token': 'invalid-token'},
                                    expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_request_invalid_signed_token(self):
        token = self.examples.INVALID_SIGNED_TOKEN
        resp = self.call_middleware(headers={'X-Auth-Token': token},
                                    expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_request_invalid_signed_pkiz_token(self):
        token = self.examples.INVALID_SIGNED_PKIZ_TOKEN
        resp = self.call_middleware(headers={'X-Auth-Token': token},
                                    expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_request_no_token(self):
        resp = self.call_middleware(expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_request_no_token_http(self):
        resp = self.call_middleware(method='HEAD', expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_request_blank_token(self):
        resp = self.call_middleware(headers={'X-Auth-Token': ''},
                                    expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def _get_cached_token(self, token, mode='md5'):
        token_id = cms.cms_hash_token(token, mode=mode)
        return self.middleware._token_cache.get(token_id)

    def test_memcache(self):
        token = self.token_dict['signed_token_scoped']
        self.call_middleware(headers={'X-Auth-Token': token})
        self.assertIsNotNone(self._get_cached_token(token))

    def test_expired(self):
        token = self.token_dict['signed_token_scoped_expired']
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)

    def test_memcache_set_invalid_uuid(self):
        invalid_uri = "%s/v2.0/tokens/invalid-token" % BASE_URI
        self.requests_mock.get(invalid_uri, status_code=404)

        token = 'invalid-token'
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)
        self.assertEqual(auth_token._CACHE_INVALID_INDICATOR,
                         self._get_cached_token(token))

    def test_memcache_hit_invalid_token(self):
        token = 'invalid-token'
        invalid_uri = '%s/v2.0/tokens/invalid-token' % BASE_URI
        self.requests_mock.get(invalid_uri, status_code=404)

        # Call once to cache token's invalid state; verify it cached as such
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)
        self.assertEqual(auth_token._CACHE_INVALID_INDICATOR,
                         self._get_cached_token(token))

        # Call again for a cache hit; verify it detected as cached and invalid
        self.call_middleware(headers={'X-Auth-Token': token},
                             expected_status=401)
        self.assertIn('Cached token is marked unauthorized',
                      self.logger.output)

    def test_memcache_set_expired(self, extra_conf={}, extra_environ={}):
        token_cache_time = 10
        conf = {
            'token_cache_time': '%s' % token_cache_time,
        }
        conf.update(extra_conf)
        self.set_middleware(conf=conf)

        token = self.token_dict['signed_token_scoped']
        self.call_middleware(headers={'X-Auth-Token': token})

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = token
        req.environ.update(extra_environ)

        now = datetime.datetime.utcnow()
        self.useFixture(TimeFixture(now))
        req.get_response(self.middleware)
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
        self.middleware._http_request_max_retries = 0
        self.call_middleware(headers={'X-Auth-Token': ERROR_TOKEN},
                             expected_status=503)
        self.assertIsNone(self._get_cached_token(ERROR_TOKEN))
        self.assert_valid_last_url(ERROR_TOKEN)

    def test_http_request_max_retries(self):
        times_retry = 10

        conf = {'http_request_max_retries': '%s' % times_retry}
        self.set_middleware(conf=conf)

        with mock.patch('time.sleep') as mock_obj:
            self.call_middleware(headers={'X-Auth-Token': ERROR_TOKEN},
                                 expected_status=503)

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

        resp = req.get_response(self.middleware)

        if success:
            self.assertEqual(200, resp.status_int)
            self.assertEqual(FakeApp.SUCCESS, resp.body)
            self.assertIn('keystone.token_info', req.environ)
            self.assert_valid_last_url(token)
        else:
            self.assertEqual(401, resp.status_int)
            msg = "Keystone uri='https://keystone.example.com:1234'"
            self.assertEqual(msg, resp.headers['WWW-Authenticate'])

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

        self.call_middleware(headers={'X-Auth-Token': token})

        self.assertThat(1, matchers.Equals(cache.set.call_count))

        self.call_middleware(headers={'X-Auth-Token': token})

        # Assert that the token wasn't cached again.
        self.assertThat(1, matchers.Equals(cache.set.call_count))

    def test_auth_plugin(self):

        for service_url in (self.examples.UNVERSIONED_SERVICE_URL,
                            self.examples.SERVICE_URL):
            self.requests_mock.get(service_url,
                                   json=VERSION_LIST_v3,
                                   status_code=300)

        token = self.token_dict['uuid_token_default']
        resp = self.call_middleware(headers={'X-Auth-Token': token})
        self.assertEqual(FakeApp.SUCCESS, resp.body)

        token_auth = resp.request.environ['keystone.token_auth']
        endpoint_filter = {'service_type': self.examples.SERVICE_TYPE,
                           'version': 3}

        url = token_auth.get_endpoint(session.Session(), **endpoint_filter)
        self.assertEqual('%s/v3' % BASE_URI, url)

        self.assertTrue(token_auth.has_user_token)
        self.assertFalse(token_auth.has_service_token)
        self.assertIsNone(token_auth.service)

    def test_doesnt_auto_set_content_type(self):
        # webob will set content_type = 'text/html' by default if nothing is
        # provided. We don't want our middleware messing with the content type
        # of the underlying applications.

        text = uuid.uuid4().hex

        def _middleware(environ, start_response):
            start_response(200, [])
            return text

        def _start_response(status_code, headerlist, exc_info=None):
            self.assertIn('200', status_code)  # will be '200 OK'
            self.assertEqual([], headerlist)

        m = auth_token.AuthProtocol(_middleware, self.conf)

        env = {'REQUEST_METHOD': 'GET',
               'HTTP_X_AUTH_TOKEN': self.token_dict['uuid_token_default']}

        r = m(env, _start_response)
        self.assertEqual(text, r)


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
        self.logger = self.useFixture(fixtures.FakeLogger())
        self.base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.base_dir)
        self.cert_dir = os.path.join(self.base_dir, 'certs')
        os.makedirs(self.cert_dir, stat.S_IRWXU)
        conf = {
            'signing_dir': self.cert_dir,
            'auth_version': self.auth_version,
        }

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.set_middleware(conf=conf)

    # Usually we supply a signed_dir with pre-installed certificates,
    # so invocation of /usr/bin/openssl succeeds. This time we give it
    # an empty directory, so it fails.
    def test_request_no_token_dummy(self):
        cms._ensure_subprocess()

        self.requests_mock.get('%s%s' % (BASE_URI, self.ca_path),
                               status_code=404)
        self.requests_mock.get('%s%s' % (BASE_URI, self.signing_path),
                               status_code=404)

        token = self.middleware._validate_offline(
            self.examples.SIGNED_TOKEN_SCOPED,
            [self.examples.SIGNED_TOKEN_SCOPED_HASH])

        self.assertIsNone(token)

        self.assertIn('Fetch certificate config failed', self.logger.output)
        self.assertIn('fallback to online validation', self.logger.output)

    def test_fetch_signing_cert(self):
        data = 'FAKE CERT'
        url = "%s%s" % (BASE_URI, self.signing_path)
        self.requests_mock.get(url, text=data)
        self.middleware._fetch_signing_cert()

        signing_cert_path = self.middleware._signing_directory.calc_path(
            self.middleware._SIGNING_CERT_FILE_NAME)
        with open(signing_cert_path, 'r') as f:
            self.assertEqual(f.read(), data)

        self.assertEqual(url, self.requests_mock.last_request.url)

    def test_fetch_signing_ca(self):
        data = 'FAKE CA'
        url = "%s%s" % (BASE_URI, self.ca_path)
        self.requests_mock.get(url, text=data)
        self.middleware._fetch_ca_cert()

        ca_file_path = self.middleware._signing_directory.calc_path(
            self.middleware._SIGNING_CA_FILE_NAME)
        with open(ca_file_path, 'r') as f:
            self.assertEqual(f.read(), data)

        self.assertEqual(url, self.requests_mock.last_request.url)

    def test_prefix_trailing_slash(self):
        del self.conf['identity_uri']
        self.conf['auth_protocol'] = 'https'
        self.conf['auth_host'] = 'keystone.example.com'
        self.conf['auth_port'] = '1234'
        self.conf['auth_admin_prefix'] = '/newadmin/'

        base_url = '%s/newadmin' % BASE_HOST
        ca_url = "%s%s" % (base_url, self.ca_path)
        signing_url = "%s%s" % (base_url, self.signing_path)

        self.requests_mock.get(base_url,
                               json=VERSION_LIST_v3,
                               status_code=300)
        self.requests_mock.get(ca_url, text='FAKECA')
        self.requests_mock.get(signing_url, text='FAKECERT')

        self.set_middleware(conf=self.conf)

        self.middleware._fetch_ca_cert()
        self.assertEqual(ca_url, self.requests_mock.last_request.url)

        self.middleware._fetch_signing_cert()
        self.assertEqual(signing_url, self.requests_mock.last_request.url)

    def test_without_prefix(self):
        del self.conf['identity_uri']
        self.conf['auth_protocol'] = 'https'
        self.conf['auth_host'] = 'keystone.example.com'
        self.conf['auth_port'] = '1234'
        self.conf['auth_admin_prefix'] = ''

        ca_url = "%s%s" % (BASE_HOST, self.ca_path)
        signing_url = "%s%s" % (BASE_HOST, self.signing_path)

        self.requests_mock.get(BASE_HOST,
                               json=VERSION_LIST_v3,
                               status_code=300)
        self.requests_mock.get(ca_url, text='FAKECA')
        self.requests_mock.get(signing_url, text='FAKECERT')

        self.set_middleware(conf=self.conf)

        self.middleware._fetch_ca_cert()
        self.assertEqual(ca_url, self.requests_mock.last_request.url)

        self.middleware._fetch_signing_cert()
        self.assertEqual(signing_url, self.requests_mock.last_request.url)


class V3CertDownloadMiddlewareTest(V2CertDownloadMiddlewareTest):

    def __init__(self, *args, **kwargs):
        super(V3CertDownloadMiddlewareTest, self).__init__(*args, **kwargs)
        self.auth_version = 'v3.0'
        self.fake_app = v3FakeApp
        self.ca_path = '/v3/OS-SIMPLE-CERT/ca'
        self.signing_path = '/v3/OS-SIMPLE-CERT/certificates'


def network_error_response(request, context):
    raise ksa_exceptions.ConnectFailure("Network connection refused.")


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

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v2,
                               status_code=300)

        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        self.revocation_url = '%s/v2.0/tokens/revoked' % BASE_URI
        self.requests_mock.get(self.revocation_url,
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
            self.requests_mock.get(url, text=text)

        url = '%s/v2.0/tokens/%s' % (BASE_URI, ERROR_TOKEN)
        self.requests_mock.get(url, text=network_error_response)

        self.set_middleware()

    def assert_unscoped_default_tenant_auto_scopes(self, token):
        """Unscoped v2 requests with a default tenant should ``auto-scope``.

        The implied scope is the user's tenant ID.

        """
        resp = self.call_middleware(headers={'X-Auth-Token': token})
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertIn('keystone.token_info', resp.request.environ)

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
        resp = self.call_middleware(headers={'X-Auth-Token': token},
                                    expected_status=401)
        self.assertEqual("Keystone uri='https://keystone.example.com:1234'",
                         resp.headers['WWW-Authenticate'])

    def test_unscoped_uuid_token_receives_401(self):
        self.assert_unscoped_token_receives_401(
            self.examples.UUID_TOKEN_UNSCOPED)

    def test_unscoped_pki_token_receives_401(self):
        self.assert_unscoped_token_receives_401(
            self.examples.SIGNED_TOKEN_UNSCOPED)

    def test_request_prevent_service_catalog_injection(self):
        token = self.examples.UUID_TOKEN_NO_SERVICE_CATALOG
        resp = self.call_middleware(headers={'X-Service-Catalog': '[]',
                                             'X-Auth-Token': token})

        self.assertFalse(resp.request.headers.get('X-Service-Catalog'))
        self.assertEqual(FakeApp.SUCCESS, resp.body)

    def test_user_plugin_token_properties(self):
        token = self.examples.UUID_TOKEN_DEFAULT
        token_data = self.examples.TOKEN_RESPONSES[token]

        resp = self.call_middleware(headers={'X-Service-Catalog': '[]',
                                             'X-Auth-Token': token,
                                             'X-Service-Token': token})

        self.assertEqual(FakeApp.SUCCESS, resp.body)

        token_auth = resp.request.environ['keystone.token_auth']

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

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        token = self.examples.UUID_TOKEN_DEFAULT
        url = "%s/v2.0/tokens/%s" % (BASE_URI, token)
        text = self.examples.JSON_TOKEN_RESPONSES[token]
        self.requests_mock.get(url, text=text)

        self.set_middleware(conf=conf)

        # This tests will only work is auth_token has chosen to use the
        # lower, v2, api version
        self.call_middleware(headers={'X-Auth-Token': token})
        self.assertEqual(url, self.requests_mock.last_request.url)


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

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v3,
                               status_code=300)

        # TODO(jamielennox): auth_token middleware uses a v2 admin token
        # regardless of the auth_version that is set.
        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        self.revocation_url = '%s/v3/auth/tokens/OS-PKI/revoked' % BASE_URI
        self.requests_mock.get(self.revocation_url,
                               text=self.examples.SIGNED_REVOCATION_LIST)

        self.requests_mock.get('%s/v3/auth/tokens' % BASE_URI,
                               text=self.token_response,
                               headers={'X-Subject-Token': uuid.uuid4().hex})

        self.set_middleware()

    def token_response(self, request, context):
        auth_id = request.headers.get('X-Auth-Token')
        token_id = request.headers.get('X-Subject-Token')
        self.assertEqual(auth_id, FAKE_ADMIN_TOKEN_ID)

        if token_id == ERROR_TOKEN:
            msg = "Network connection refused."
            raise ksa_exceptions.ConnectFailure(msg)

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
        self.requests_mock.get('%s/v3/OS-SIMPLE-CERT/certificates' % BASE_URI,
                               status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_fallback_to_online_validation_with_ca_error(self):
        self.requests_mock.get('%s/v3/OS-SIMPLE-CERT/ca' % BASE_URI,
                               status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_fallback_to_online_validation_with_revocation_list_error(self):
        self.requests_mock.get(self.revocation_url, status_code=404)
        self.assert_valid_request_200(self.token_dict['signed_token_scoped'])
        self.assert_valid_request_200(
            self.token_dict['signed_token_scoped_pkiz'])

    def test_user_plugin_token_properties(self):
        token = self.examples.v3_UUID_TOKEN_DEFAULT
        token_data = self.examples.TOKEN_RESPONSES[token]

        resp = self.call_middleware(headers={'X-Service-Catalog': '[]',
                                             'X-Auth-Token': token,
                                             'X-Service-Token': token})

        self.assertEqual(FakeApp.SUCCESS, resp.body)

        token_auth = resp.request.environ['keystone.token_auth']

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

    def test_expire_stored_in_cache(self):
        # tests the upgrade path from storing a tuple vs just the data in the
        # cache. Can be removed in the future.
        token = 'mytoken'
        data = 'this_data'
        self.set_middleware()
        self.middleware._token_cache.initialize({})
        now = datetime.datetime.utcnow()
        delta = datetime.timedelta(hours=1)
        expires = strtime(at=(now + delta))
        self.middleware._token_cache.set(token, (data, expires))
        new_data = self.middleware.fetch_token(token)
        self.assertEqual(data, new_data)


class DelayedAuthTests(BaseAuthTokenMiddlewareTest):

    def test_header_in_401(self):
        body = uuid.uuid4().hex
        auth_uri = 'http://local.test'
        conf = {'delay_auth_decision': 'True',
                'auth_version': 'v3.0',
                'auth_uri': auth_uri}

        middleware = self.create_simple_middleware(status='401 Unauthorized',
                                                   body=body,
                                                   conf=conf)
        resp = self.call(middleware, expected_status=401)
        self.assertEqual(six.b(body), resp.body)

        self.assertEqual("Keystone uri='%s'" % auth_uri,
                         resp.headers['WWW-Authenticate'])

    def test_delayed_auth_values(self):
        conf = {'auth_uri': 'http://local.test'}
        status = '401 Unauthorized'

        middleware = self.create_simple_middleware(status=status, conf=conf)
        self.assertFalse(middleware._delay_auth_decision)

        for v in ('True', '1', 'on', 'yes'):
            conf = {'delay_auth_decision': v,
                    'auth_uri': 'http://local.test'}

            middleware = self.create_simple_middleware(status=status,
                                                       conf=conf)
            self.assertTrue(middleware._delay_auth_decision)

        for v in ('False', '0', 'no'):
            conf = {'delay_auth_decision': v,
                    'auth_uri': 'http://local.test'}

            middleware = self.create_simple_middleware(status=status,
                                                       conf=conf)
            self.assertFalse(middleware._delay_auth_decision)

    def test_auth_plugin_with_no_tokens(self):
        body = uuid.uuid4().hex
        auth_uri = 'http://local.test'
        conf = {'delay_auth_decision': True, 'auth_uri': auth_uri}

        middleware = self.create_simple_middleware(body=body, conf=conf)
        resp = self.call(middleware)
        self.assertEqual(six.b(body), resp.body)

        token_auth = resp.request.environ['keystone.token_auth']

        self.assertFalse(token_auth.has_user_token)
        self.assertIsNone(token_auth.user)
        self.assertFalse(token_auth.has_service_token)
        self.assertIsNone(token_auth.service)


class CommonCompositeAuthTests(object):
    """Test Composite authentication.

    Test the behaviour of adding a service-token.
    """

    def test_composite_auth_ok(self):
        token = self.token_dict['uuid_token_default']
        service_token = self.token_dict['uuid_service_token_default']
        fake_logger = fixtures.FakeLogger(level=logging.DEBUG)
        self.middleware.logger = self.useFixture(fake_logger)
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token})
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        expected_env = dict(EXPECTED_V2_DEFAULT_ENV_RESPONSE)
        expected_env.update(EXPECTED_V2_DEFAULT_SERVICE_ENV_RESPONSE)

        # role list may get reordered, check for string pieces individually
        self.assertIn('Received request from user: ', fake_logger.output)
        self.assertIn('user_id %(HTTP_X_USER_ID)s, '
                      'project_id %(HTTP_X_TENANT_ID)s, '
                      'roles ' % expected_env, fake_logger.output)
        self.assertIn('service: user_id %(HTTP_X_SERVICE_USER_ID)s, '
                      'project_id %(HTTP_X_SERVICE_PROJECT_ID)s, '
                      'roles ' % expected_env, fake_logger.output)

        roles = ','.join([expected_env['HTTP_X_SERVICE_ROLES'],
                          expected_env['HTTP_X_ROLES']])

        for r in roles.split(','):
            self.assertIn(r, fake_logger.output)

    def test_composite_auth_invalid_service_token(self):
        token = self.token_dict['uuid_token_default']
        service_token = 'invalid-service-token'
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token},
                                    expected_status=401)
        expected_body = b'The request you have made requires authentication.'
        self.assertThat(resp.body, matchers.Contains(expected_body))

    def test_composite_auth_no_service_token(self):
        self.purge_service_token_expected_env()
        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['uuid_token_default']

        # Ensure injection of service headers is not possible
        for key, value in six.iteritems(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            req.headers[header_key] = value
        # Check arbitrary headers not removed
        req.headers['X-Foo'] = 'Bar'
        resp = req.get_response(self.middleware)
        for key in six.iterkeys(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            self.assertFalse(req.headers.get(header_key))
        self.assertEqual('Bar', req.headers.get('X-Foo'))
        self.assertEqual(418, resp.status_int)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def test_composite_auth_invalid_user_token(self):
        token = 'invalid-token'
        service_token = self.token_dict['uuid_service_token_default']
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token},
                                    expected_status=401)
        expected_body = b'The request you have made requires authentication.'
        self.assertThat(resp.body, matchers.Contains(expected_body))

    def test_composite_auth_no_user_token(self):
        service_token = self.token_dict['uuid_service_token_default']
        resp = self.call_middleware(headers={'X-Service-Token': service_token},
                                    expected_status=401)
        expected_body = b'The request you have made requires authentication.'
        self.assertThat(resp.body, matchers.Contains(expected_body))

    def test_composite_auth_delay_ok(self):
        self.middleware._delay_auth_decision = True
        token = self.token_dict['uuid_token_default']
        service_token = self.token_dict['uuid_service_token_default']
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token})
        self.assertEqual(FakeApp.SUCCESS, resp.body)

    def test_composite_auth_delay_invalid_service_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_service_token_expected_env()
        expected_env = {
            'HTTP_X_SERVICE_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        token = self.token_dict['uuid_token_default']
        service_token = 'invalid-service-token'
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token},
                                    expected_status=420)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def test_composite_auth_delay_invalid_service_and_user_tokens(self):
        self.middleware._delay_auth_decision = True
        self.purge_service_token_expected_env()
        self.purge_token_expected_env()
        expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Invalid',
            'HTTP_X_SERVICE_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        token = 'invalid-token'
        service_token = 'invalid-service-token'
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token},
                                    expected_status=419)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def test_composite_auth_delay_no_service_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_service_token_expected_env()

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = self.token_dict['uuid_token_default']

        # Ensure injection of service headers is not possible
        for key, value in six.iteritems(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            req.headers[header_key] = value
        # Check arbitrary headers not removed
        req.headers['X-Foo'] = 'Bar'
        resp = req.get_response(self.middleware)
        for key in six.iterkeys(self.service_token_expected_env):
            header_key = key[len('HTTP_'):].replace('_', '-')
            self.assertFalse(req.headers.get(header_key))
        self.assertEqual('Bar', req.headers.get('X-Foo'))
        self.assertEqual(418, resp.status_int)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def test_composite_auth_delay_invalid_user_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_token_expected_env()
        expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        token = 'invalid-token'
        service_token = self.token_dict['uuid_service_token_default']
        resp = self.call_middleware(headers={'X-Auth-Token': token,
                                             'X-Service-Token': service_token},
                                    expected_status=403)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def test_composite_auth_delay_no_user_token(self):
        self.middleware._delay_auth_decision = True
        self.purge_token_expected_env()
        expected_env = {
            'HTTP_X_IDENTITY_STATUS': 'Invalid',
        }
        self.update_expected_env(expected_env)

        service_token = self.token_dict['uuid_service_token_default']
        resp = self.call_middleware(headers={'X-Service-Token': service_token},
                                    expected_status=403)
        self.assertEqual(FakeApp.FORBIDDEN, resp.body)

    def assert_kerberos_composite_bind(self, user_token, service_token,
                                       bind_level):
        conf = {
            'enforce_token_bind': bind_level,
            'auth_version': self.auth_version,
        }
        self.set_middleware(conf=conf)

        req = webob.Request.blank('/')
        req.headers['X-Auth-Token'] = user_token
        req.headers['X-Service-Token'] = service_token

        req.environ['REMOTE_USER'] = self.examples.SERVICE_KERBEROS_BIND
        req.environ['AUTH_TYPE'] = 'Negotiate'

        resp = req.get_response(self.middleware)

        self.assertEqual(200, resp.status_int)
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertIn('keystone.token_info', req.environ)

    def test_composite_auth_with_bind(self):
        token = self.token_dict['uuid_token_bind']
        service_token = self.token_dict['uuid_service_token_bind']

        self.assert_kerberos_composite_bind(token,
                                            service_token,
                                            bind_level='required')


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
        uuid_token_bind = self.examples.UUID_TOKEN_BIND
        uuid_service_token_bind = self.examples.UUID_SERVICE_TOKEN_BIND
        self.token_dict = {
            'uuid_token_default': uuid_token_default,
            'uuid_service_token_default': uuid_service_token_default,
            'uuid_token_bind': uuid_token_bind,
            'uuid_service_token_bind': uuid_service_token_bind,
        }

        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v2,
                               status_code=300)

        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        self.requests_mock.get('%s/v2.0/tokens/revoked' % BASE_URI,
                               text=self.examples.SIGNED_REVOCATION_LIST,
                               status_code=200)

        for token in (self.examples.UUID_TOKEN_DEFAULT,
                      self.examples.UUID_SERVICE_TOKEN_DEFAULT,
                      self.examples.UUID_TOKEN_BIND,
                      self.examples.UUID_SERVICE_TOKEN_BIND):
            text = self.examples.JSON_TOKEN_RESPONSES[token]
            self.requests_mock.get('%s/v2.0/tokens/%s' % (BASE_URI, token),
                                   text=text)

        for invalid_uri in ("%s/v2.0/tokens/invalid-token" % BASE_URI,
                            "%s/v2.0/tokens/invalid-service-token" % BASE_URI):
            self.requests_mock.get(invalid_uri, text='', status_code=404)

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
        uuid_token_bind = self.examples.v3_UUID_TOKEN_BIND
        uuid_service_token_bind = self.examples.v3_UUID_SERVICE_TOKEN_BIND
        self.token_dict = {
            'uuid_token_default': uuid_token_default,
            'uuid_service_token_default': uuid_serv_token_default,
            'uuid_token_bind': uuid_token_bind,
            'uuid_service_token_bind': uuid_service_token_bind,
        }

        self.requests_mock.get(BASE_URI, json=VERSION_LIST_v3, status_code=300)

        # TODO(jamielennox): auth_token middleware uses a v2 admin token
        # regardless of the auth_version that is set.
        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)

        self.requests_mock.get('%s/v3/auth/tokens/OS-PKI/revoked' % BASE_URI,
                               text=self.examples.SIGNED_REVOCATION_LIST)

        self.requests_mock.get('%s/v3/auth/tokens' % BASE_URI,
                               text=self.token_response,
                               headers={'X-Subject-Token': uuid.uuid4().hex})

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
            msg = "Network connection refused."
            raise ksc_exceptions.ConnectionRefused(msg)

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

        self.requests_mock.get(BASE_URI, json=versions, status_code=300)

        self.call_middleware(headers={'X-Auth-Token': uuid.uuid4().hex},
                             expected_status=503)

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
        self.requests_mock.get(BASE_URI, json=VERSION_LIST_v3, status_code=300)
        self._assert_auth_version(None, (3, 0))

        # VERSION_LIST_v2 contains only v2 version elements
        self.requests_mock.get(BASE_URI, json=VERSION_LIST_v2, status_code=300)
        self._assert_auth_version(None, (2, 0))

    def test_unsupported_auth_version(self):
        # If the requested version isn't supported we will use v2
        self._assert_auth_version('v1', (2, 0))
        self._assert_auth_version('v10', (2, 0))


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

        self.project_id = uuid.uuid4().hex

        # first touch is to discover the available versions at the auth_url
        self.requests_mock.get(self.AUTH_URL,
                               json=fixture.DiscoveryList(href=self.DISC_URL),
                               status_code=300)

        # then we do discovery on the URL from the service catalog. In practice
        # this is mostly the same URL as before but test the full range.
        self.requests_mock.get(self.KEYSTONE_BASE_URL + '/',
                               json=fixture.DiscoveryList(href=self.CRUD_URL),
                               status_code=300)

    def good_request(self, app):
        # admin_token is the token that the service will get back from auth
        admin_token_id = uuid.uuid4().hex
        admin_token = fixture.V3Token(project_id=self.project_id)
        s = admin_token.add_service('identity', name='keystone')
        s.add_standard_endpoints(admin=self.KEYSTONE_URL)

        self.requests_mock.post(self.DISC_URL + '/v3/auth/tokens',
                                json=admin_token,
                                headers={'X-Subject-Token': admin_token_id})

        # user_token is the data from the user's inputted token
        user_token_id = uuid.uuid4().hex
        user_token = fixture.V3Token()
        user_token.set_project_scope()

        request_headers = {'X-Subject-Token': user_token_id,
                           'X-Auth-Token': admin_token_id}

        self.requests_mock.get(self.CRUD_URL + '/v3/auth/tokens',
                               request_headers=request_headers,
                               json=user_token,
                               headers={'X-Subject-Token': uuid.uuid4().hex})

        resp = self.call(app, headers={'X-Auth-Token': user_token_id})
        return resp

    def test_loading_password_plugin(self):
        # the password options aren't set on config until loading time, but we
        # need them set so we can override the values for testing, so force it
        opts = loading.get_auth_plugin_conf_options('password')
        self.cfg.register_opts(opts, group=_base.AUTHTOKEN_GROUP)

        project_id = uuid.uuid4().hex

        # Register the authentication options
        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)

        # configure the authentication options
        self.cfg.config(auth_type='password',
                        username='testuser',
                        password='testpass',
                        auth_url=self.AUTH_URL,
                        project_id=project_id,
                        user_domain_id='userdomainid',
                        group=_base.AUTHTOKEN_GROUP)

        body = uuid.uuid4().hex
        app = self.create_simple_middleware(body=body)

        resp = self.good_request(app)
        self.assertEqual(six.b(body), resp.body)

    @staticmethod
    def get_plugin(app):
        return app._identity_server._adapter.auth

    def test_invalid_plugin_fails_to_initialize(self):
        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)
        self.cfg.config(auth_type=uuid.uuid4().hex,
                        group=_base.AUTHTOKEN_GROUP)

        self.assertRaises(
            ksa_exceptions.NoMatchingPlugin,
            self.create_simple_middleware)

    def test_plugin_loading_mixed_opts(self):
        # some options via override and some via conf
        opts = loading.get_auth_plugin_conf_options('password')
        self.cfg.register_opts(opts, group=_base.AUTHTOKEN_GROUP)

        username = 'testuser'
        password = 'testpass'

        # Register the authentication options
        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)

        # configure the authentication options
        self.cfg.config(auth_type='password',
                        auth_url='http://keystone.test:5000',
                        password=password,
                        project_id=self.project_id,
                        user_domain_id='userdomainid',
                        group=_base.AUTHTOKEN_GROUP)

        conf = {'username': username, 'auth_url': self.AUTH_URL}

        body = uuid.uuid4().hex
        app = self.create_simple_middleware(body=body, conf=conf)

        resp = self.good_request(app)
        self.assertEqual(six.b(body), resp.body)

        plugin = self.get_plugin(app)

        self.assertEqual(self.AUTH_URL, plugin.auth_url)
        self.assertEqual(username, plugin._username)
        self.assertEqual(password, plugin._password)
        self.assertEqual(self.project_id, plugin._project_id)

    def test_plugin_loading_with_auth_section(self):
        # some options via override and some via conf
        section = 'testsection'
        username = 'testuser'
        password = 'testpass'

        loading.register_auth_conf_options(self.cfg.conf, group=section)
        opts = loading.get_auth_plugin_conf_options('password')
        self.cfg.register_opts(opts, group=section)

        # Register the authentication options
        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)

        # configure the authentication options
        self.cfg.config(auth_section=section, group=_base.AUTHTOKEN_GROUP)
        self.cfg.config(auth_type='password',
                        auth_url=self.AUTH_URL,
                        password=password,
                        project_id=self.project_id,
                        user_domain_id='userdomainid',
                        group=section)

        conf = {'username': username}

        body = uuid.uuid4().hex
        app = self.create_simple_middleware(body=body, conf=conf)

        resp = self.good_request(app)
        self.assertEqual(six.b(body), resp.body)

        plugin = self.get_plugin(app)

        self.assertEqual(self.AUTH_URL, plugin.auth_url)
        self.assertEqual(username, plugin._username)
        self.assertEqual(password, plugin._password)
        self.assertEqual(self.project_id, plugin._project_id)


class TestAuthPluginUserAgentGeneration(BaseAuthTokenMiddlewareTest):

    def setUp(self):
        super(TestAuthPluginUserAgentGeneration, self).setUp()
        self.auth_url = uuid.uuid4().hex
        self.project_id = uuid.uuid4().hex
        self.username = uuid.uuid4().hex
        self.password = uuid.uuid4().hex
        self.section = uuid.uuid4().hex
        self.user_domain_id = uuid.uuid4().hex

        loading.register_auth_conf_options(self.cfg.conf, group=self.section)
        opts = loading.get_auth_plugin_conf_options('password')
        self.cfg.register_opts(opts, group=self.section)

        # Register the authentication options
        loading.register_auth_conf_options(self.cfg.conf,
                                           group=_base.AUTHTOKEN_GROUP)

        # configure the authentication options
        self.cfg.config(auth_section=self.section, group=_base.AUTHTOKEN_GROUP)
        self.cfg.config(auth_type='password',
                        password=self.password,
                        project_id=self.project_id,
                        user_domain_id=self.user_domain_id,
                        group=self.section)

    def test_no_project_configured(self):
        ksm_version = uuid.uuid4().hex
        conf = {'username': self.username, 'auth_url': self.auth_url}

        app = self._create_app(conf, ksm_version)
        self._assert_user_agent(app, '', ksm_version)

    def test_project_in_configuration(self):
        project = uuid.uuid4().hex
        project_version = uuid.uuid4().hex

        conf = {'username': self.username,
                'auth_url': self.auth_url,
                'project': project}
        app = self._create_app(conf, project_version)
        project_with_version = '{0}/{1} '.format(project, project_version)
        self._assert_user_agent(app, project_with_version, project_version)

    def test_project_not_installed_results_in_unknown_version(self):
        project = uuid.uuid4().hex

        conf = {'username': self.username,
                'auth_url': self.auth_url,
                'project': project}

        v = pkg_resources.get_distribution('keystonemiddleware').version

        app = self.create_simple_middleware(conf=conf, use_global_conf=True)
        project_with_version = '{0}/{1} '.format(project, 'unknown')
        self._assert_user_agent(app, project_with_version, v)

    def test_project_in_oslo_configuration(self):
        project = uuid.uuid4().hex
        project_version = uuid.uuid4().hex

        conf = {'username': self.username, 'auth_url': self.auth_url}
        with mock.patch.object(cfg.CONF, 'project', new=project, create=True):
            app = self._create_app(conf, project_version)
        project = '{0}/{1} '.format(project, project_version)
        self._assert_user_agent(app, project, project_version)

    def _create_app(self, conf, project_version):
        fake_pkg_resources = mock.Mock()
        fake_pkg_resources.get_distribution().version = project_version

        body = uuid.uuid4().hex
        with mock.patch('keystonemiddleware.auth_token.pkg_resources',
                        new=fake_pkg_resources):
            return self.create_simple_middleware(body=body, conf=conf,
                                                 use_global_conf=True)

    def _assert_user_agent(self, app, project, ksm_version):
        sess = app._identity_server._adapter.session
        expected_ua = ('{0}keystonemiddleware.auth_token/{1}'
                       .format(project, ksm_version))
        self.assertThat(sess.user_agent, matchers.StartsWith(expected_ua))


class TestAuthPluginLocalOsloConfig(BaseAuthTokenMiddlewareTest):

    def setUp(self):
        super(TestAuthPluginLocalOsloConfig, self).setUp()
        self.project = uuid.uuid4().hex

        # NOTE(cdent): The options below are selected from those
        # which are statically registered by auth_token middleware
        # in the 'keystone_authtoken' group. Additional options, from
        # plugins, are registered dynamically so must not be used here.
        self.oslo_options = {
            'auth_uri': uuid.uuid4().hex,
            'identity_uri': uuid.uuid4().hex,
        }

        self.local_oslo_config = cfg.ConfigOpts()
        self.local_oslo_config.register_group(cfg.OptGroup(
            name='keystone_authtoken'))
        self.local_oslo_config.register_opts(auth_token._OPTS,
                                             group='keystone_authtoken')
        self.local_oslo_config.register_opts(auth_token._auth.OPTS,
                                             group='keystone_authtoken')
        for option, value in self.oslo_options.items():
            self.local_oslo_config.set_override(option, value,
                                                'keystone_authtoken')
        self.local_oslo_config(args=[], project=self.project)

        self.file_options = {
            'auth_type': 'password',
            'auth_uri': uuid.uuid4().hex,
            'password': uuid.uuid4().hex,
        }

        content = ("[keystone_authtoken]\n"
                   "auth_type=%(auth_type)s\n"
                   "auth_uri=%(auth_uri)s\n"
                   "auth_url=%(auth_uri)s\n"
                   "password=%(password)s\n" % self.file_options)
        self.conf_file_fixture = self.useFixture(
            createfile.CreateFileWithContent(self.project, content))

    def test_project_in_local_oslo_configuration(self):
        conf = {'oslo_config_project': self.project,
                'oslo_config_file': self.conf_file_fixture.path}
        app = self._create_app(conf, uuid.uuid4().hex)
        for option in self.file_options:
            self.assertEqual(self.file_options[option],
                             app._conf_get(option), option)

    def test_passed_oslo_configuration(self):
        conf = {'oslo_config_config': self.local_oslo_config}
        app = self._create_app(conf, uuid.uuid4().hex)
        for option in self.oslo_options:
            self.assertEqual(self.oslo_options[option],
                             app._conf_get(option))

    def test_passed_olso_configuration_wins(self):
        """oslo_config_config has precedence over oslo_config_project."""
        conf = {'oslo_config_project': self.project,
                'oslo_config_config': self.local_oslo_config,
                'oslo_config_file': self.conf_file_fixture.path}
        app = self._create_app(conf, uuid.uuid4().hex)
        for option in self.oslo_options:
            self.assertEqual(self.oslo_options[option],
                             app._conf_get(option))
        self.assertNotEqual(self.file_options['auth_uri'],
                            app._conf_get('auth_uri'))

    def _create_app(self, conf, project_version):
        fake_pkg_resources = mock.Mock()
        fake_pkg_resources.get_distribution().version = project_version

        body = uuid.uuid4().hex
        with mock.patch('keystonemiddleware.auth_token.pkg_resources',
                        new=fake_pkg_resources):
            # use_global_conf is poorly named. What it means is
            # don't use the config created in test setUp.
            return self.create_simple_middleware(body=body, conf=conf,
                                                 use_global_conf=True)


def load_tests(loader, tests, pattern):
    return testresources.OptimisingTestSuite(tests)
