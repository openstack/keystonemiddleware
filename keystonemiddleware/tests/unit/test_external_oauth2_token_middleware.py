# Copyright 2023 OpenStack Foundation
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

import base64
import copy
import hashlib
from http import HTTPStatus
import jwt.utils
import logging
import ssl
from testtools import matchers
import time
from unittest import mock
import uuid
import webob.dec

import fixtures
from oslo_config import cfg
import testresources

from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import session

from keystonemiddleware.auth_token import _cache
from keystonemiddleware import external_oauth2_token
from keystonemiddleware.tests.unit.auth_token import base
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FakeApp
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import v3FakeApp
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import VERSION_LIST_v3
from keystonemiddleware.tests.unit import client_fixtures
from keystonemiddleware.tests.unit import utils

JWT_KEY_CONTENT = (
    '-----BEGIN PRIVATE KEY-----\n'
    'MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDegNuQgmQL7n10\n'
    '+Z3itXtpiNHlvZwCYOS66+3PakAw1OoRB6SiHeNYnuVRHlraTDKnnfgHhX/1AVs7\n'
    'P36QU5PVYznGip2PXZlCh8MeQhpXgKKt25LPnpQOnUssHyq+OqTHZB6eS2C7xMHf\n'
    'wzPrYRwxhbVgUUVe85cdiXaL5ZRqXNotM00wH1hck4s+1fsnKv7UeGbwM1WwMn6/\n'
    '0E1eKwYzlKm4Vmkcivy8WBI7Ijp/MPOUyRXN/mPh8L2VOq0D1E3pufYoYmpBkiQi\n'
    'Ii8nz5CXrhDpM0tGKD+RZ+howE2i+frI2gNDfU5xMx+k+qjD0jftDrQ+OZUujUtq\n'
    '6JfdrvtPBT01XZw8GV5Rm9vEwMRduWUDGdRB3chOTeTUdsIG765+Ot7GE7nYrAs0\n'
    's/ryAm1FnNJocTzje7k07IzdBpWzrTrx087Kfcsn6evEABOxim0i+AHUR94QR9/V\n'
    'EP3/+SkJ7zl9P1KzOZZCWtUTnfQxrLhEnCwwjtl35vWlzst+TR7HDwIzQRQVLFH9\n'
    'zMTz8tw6coPifkbVzdwCLGoKge4llDPcVx/TmIGFD3saT0E68yxXe6k3cdIg6lZf\n'
    'dB0yutVBzECrx+LiIpxwQWRKHNiR58KsHHmgXDb8ORBCjpmctD+JsdBhf8hDRMXP\n'
    '9sV/fbMUwgrRceyj9AV2x59tE9+UHwIDAQABAoICABb6V7JkxNA2oN4jqRpwg34y\n'
    'kvqWyjW0q+ph0v1Ii7h/RGzdzTKww3mzbxshd2Bz3gdRWPvt3Xj/2twTgo6FEw9G\n'
    'YAEQ75SOpfUo8A1/5hiDQEmUE2U9iyy3Mbwsu81JYRr2S/Ms9aBugVcKYaI9NRwo\n'
    'IsL/oZpcrY5vU76+xsT1MdLZKW9+zTFCS28Byh4RYp+uj3Le2kqH7G8Co/rFlq5c\n'
    '++n9gn1gHRmWPsu8jS31cDI9UfMkAkyi//EZTiTHGAS7H6CsCS0cWn7r6NLDrLr9\n'
    'TuHGWk+0eFwbzvSCZ4IdLrjvSsb9ecxW6z2uZR9T5lKk4hhK+g0EqnUv7/8Eww8E\n'
    'wA2J1zhuQ0UzoAowjj5338whBQROKSO4u3ppxhNUSP7fUgYdEKUQEg7rlfEzI+pG\n'
    'dV1LtG0GZBzdZXpE/PTpASjefCkC6olmZpUvajHJGqP0a/ygA9SEBm+B/Q4ii7+0\n'
    'luk6Lj6z+vSWatU7LrLnQeprN82NWxtkH+u2gjMOq1N8r4FOFvbZYBp1NMvtH4iP\n'
    'R6jLdJWYx/KOr4lCkbgTszlVhPop8dktOPQSPL4u6RxdmsGBf028oWKXLrj1D1Ua\n'
    'dBWR1L1CCnI8X6jxL6eT52qF+NY2JxanX6NnzxE/KqedWXmKDxn0M3ETfizz9UG4\n'
    '8UmsMgJ8UUALRbWHjlEBAoIBAQDvQmYWhYtUQjcaeLkhjd9qPXjLGIL6NYnrYEUK\n'
    'Yenn0mh7SKZTTL8yz/QVOecD/QiBetmQJ5FsmUmqorGWYfbWs6C+p2yHQ0U9X7rE\n'
    '3ynFm0MDluuNZMWYRu0Yb6gvCYjitlt/efGKDalP1Al1hX2w9fUGdj32K6fulEX6\n'
    'dcl4r2bq4i+rOwe9YDD9yvkvh1+aCwA56JCTBoEBsbmOdKTC7431rT8BTLbBaXwy\n'
    'hf35P9wzU079QwwqDKdUlMQjUz9gWZkYFHkPfce2MCm+T0aHNnjQtLXRGOcIj15P\n'
    'B64+GB9b86XNZlqpuY2rceF+LDwaw4rgQkXDr+TdAsjrtcdHAoIBAQDuElNxRc9t\n'
    'hKwZGBVIWaHI3Y3oaTymi277DwhDzvmJgwBAddfEaC1rCt/giXxtmhhnAXpDD4sk\n'
    '3m8iWw1jODRxOv2UDkUvSRV5tfY+QTG0nVVmMpX3lPWpIYxEVg34WYSq0xnXKrpW\n'
    'zxUOqD1fW2i2lXZtFAb6ZNt/hHts7KUPzk9/ZbAomVHO6JO4Ac3n0LTDSCmQHhRO\n'
    '5gV0ea4Sh6AVOiFD20rMAnTFNnxnI+wLMt0SNAzouhRMulDqOcAmoH2DKG8PCcEt\n'
    'dQpUDwITxXuomsjhIHIli760MwSlwWZbrh5h7NAj1VmnQBtMkLnBtnE7cFSVdcPt\n'
    'BAFnq72txGhpAoIBAQDIWYKhM1zTxsrbyOHF3kaKcUVYVINBQFnolunZYtp6vG+v\n'
    'ZMuaj3a/9vE+YQk5Bsb7ncLXerrFBKtyTuCEvC315d8iJ5KyxbsSRLpiJzmUdoos\n'
    'VFGVSiBIfoQF5WIhWUueBPQjkBqZ7wyrgzQUjB8PczamHZePL0lleBYNQFrgS4jU\n'
    'AWnHahv2EbmUnEYD7ck5diLPWxbNdzHKGGf4iWZ6shze8B8FWJbk6Q8OQ7PD5xze\n'
    'gdFwNJfYElaAdj60Ef7NENopFuO0/C+jOTuLWFkH2q5anihuGvtD6MIhTZ4z8wE3\n'
    'f5SEpkQfQfkG6srXW/VMuBfv6K8AyabNB4r2Dnb7AoIBADHy2lrroKeDrG/fY6e4\n'
    'Vn9ELJ/UZIs0ueYmsz82z5gQSh88Gjb0/IJ2153OerKsH+6MmtAzFKh5mquEmvx0\n'
    'MFyJWeaUT+Op272bdbx+BSW11NMKTfiR4jDH/xvfSjMO5QzKGaPRLSNFc0+N8MJu\n'
    '9TtJhH1CNGyYeIz6iMLDq6XzTS6XcSwzbryQg12Z00+NtD88hqvcA7rB++cCGIl+\n'
    'txF9Drmj6r9+zG0MD3G8UavP0h4dmY/CarvmY0+hKjVweqTn+NUY4NTet3oHZBIt\n'
    '3tHzF65UFl7WQP6hrZnxR754e5tkCg9aleLHSnL38mE4G+2ylax99stlib3shHFO\n'
    'wfECggEBAJrW8BmZXbD8ss3c7kHPzleAf1q/6bPnxRXB0luCPz7tkMfdkOQ2cG1t\n'
    'rcnsKcyR2woEbtdRK938KxZgTgzKYVhR8spKFSh01/d9OZAP6f+iCoR2zzOlSFo4\n'
    'pejnQY0LHEwGZmnzghLoqJSUgROAR49CvLO1mI48CaEUuLmqzPYWNXMHDDU2N5XO\n'
    'uF0/ph68fnI+f+0ZUgdpVPFRnfSrAqzEhzEMh1vnZ4ZxEVpgUcn/hRfNZ3hN0LEr\n'
    'fjm2bWxg2j0rxjS0mUDQpaMj0253jVYRiC3M3cCh0NSZtwaXVJYCVxetpjBTPfJr\n'
    'jIgmPTKGR0FedjAeCBByH9vkw8iRg7w=\n'
    '-----END PRIVATE KEY-----\n')

MEMCACHED_SERVERS = ['localhost:11211']


def get_authorization_header(token):
    return {'Authorization': f'Bearer {token}'}


def get_config(
        introspect_endpoint=None,
        audience=None,
        auth_method=None,
        client_id=None,
        client_secret=None,
        thumbprint_verify=None,
        jwt_key_file=None,
        jwt_algorithm=None,
        jwt_bearer_time_out=None,
        mapping_project_id=None,
        mapping_project_name=None,
        mapping_project_domain_id=None,
        mapping_project_domain_name=None,
        mapping_user_id=None,
        mapping_user_name=None,
        mapping_user_domain_id=None,
        mapping_user_domain_name=None,
        mapping_roles=None,
        mapping_system_scope=None,
        mapping_expires_at=None,
        memcached_servers=None,
        memcache_use_advanced_pool=None,
        memcache_pool_dead_retry=None,
        memcache_pool_maxsize=None,
        memcache_pool_unused_timeout=None,
        memcache_pool_conn_get_timeout=None,
        memcache_pool_socket_timeout=None,
        memcache_security_strategy=None,
        memcache_secret_key=None):
    conf = {}
    if introspect_endpoint is not None:
        conf['introspect_endpoint'] = introspect_endpoint
    if audience is not None:
        conf['audience'] = audience
    if auth_method is not None:
        conf['auth_method'] = auth_method
    if client_id is not None:
        conf['client_id'] = client_id
    if client_secret is not None:
        conf['client_secret'] = client_secret
    if jwt_key_file is not None:
        conf['jwt_key_file'] = jwt_key_file
    if jwt_algorithm is not None:
        conf['jwt_algorithm'] = jwt_algorithm
    if jwt_bearer_time_out is not None:
        conf['jwt_bearer_time_out'] = jwt_bearer_time_out
    if thumbprint_verify is not None:
        conf['thumbprint_verify'] = thumbprint_verify
    if mapping_project_id is not None:
        conf['mapping_project_id'] = mapping_project_id
    if mapping_project_name is not None:
        conf['mapping_project_name'] = mapping_project_name
    if mapping_project_id is not None:
        conf['mapping_project_domain_id'] = mapping_project_domain_id
    if mapping_project_domain_name is not None:
        conf['mapping_project_domain_name'] = mapping_project_domain_name
    if mapping_user_id is not None:
        conf['mapping_user_id'] = mapping_user_id
    if mapping_project_id is not None:
        conf['mapping_project_id'] = mapping_project_id
    if mapping_user_name is not None:
        conf['mapping_user_name'] = mapping_user_name
    if mapping_user_domain_id is not None:
        conf['mapping_user_domain_id'] = mapping_user_domain_id
    if mapping_project_id is not None:
        conf['mapping_user_domain_name'] = mapping_user_domain_name
    if mapping_roles is not None:
        conf['mapping_roles'] = mapping_roles
    if mapping_system_scope is not None:
        conf['mapping_system_scope'] = mapping_system_scope
    if memcached_servers is not None:
        conf['memcached_servers'] = memcached_servers
    if memcached_servers is not None:
        conf['mapping_expires_at'] = mapping_expires_at
    if memcache_use_advanced_pool is not None:
        conf['memcache_use_advanced_pool'] = memcache_use_advanced_pool
    if memcache_pool_dead_retry is not None:
        conf['memcache_pool_dead_retry'] = memcache_pool_dead_retry
    if memcache_pool_maxsize is not None:
        conf['memcache_pool_maxsize'] = memcache_pool_maxsize
    if memcache_pool_unused_timeout is not None:
        conf['memcache_pool_unused_timeout'] = memcache_pool_unused_timeout
    if memcache_pool_conn_get_timeout is not None:
        conf['memcache_pool_conn_get_timeout'] = memcache_pool_conn_get_timeout
    if memcache_pool_socket_timeout is not None:
        conf['memcache_pool_socket_timeout'] = memcache_pool_socket_timeout
    if memcache_security_strategy is not None:
        conf['memcache_security_strategy'] = memcache_security_strategy
    if memcache_secret_key is not None:
        conf['memcache_secret_key'] = memcache_secret_key

    return conf


class FakeOauth2TokenV3App(v3FakeApp):

    def __init__(self,
                 expected_env=None,
                 need_service_token=False,
                 app_response_status_code=200):
        super(FakeOauth2TokenV3App, self).__init__(expected_env,
                                                   need_service_token)

        self._status_code = app_response_status_code

    @webob.dec.wsgify
    def __call__(self, req):
        resp = webob.Response()
        if self._status_code == 200:
            resp.status_code = 200
            resp.body = FakeApp.SUCCESS
        else:
            resp.status_code = self._status_code
            resp.body = b'Error'

        return resp


class FakeSocket(object):

    def __init__(self, binary_peer_cert):
        self.binary_peer_cert = binary_peer_cert

    def getpeercert(self, binary_form=True):
        if binary_form:
            return self.binary_peer_cert
        else:
            return None


class FakeWsgiInput(object):

    def __init__(self, fake_socket):
        self.fake_socket = fake_socket

    def get_socket(self):
        return self.fake_socket


class BaseExternalOauth2TokenMiddlewareTest(base.BaseAuthTokenTestCase,
                                            testresources.ResourcedTestCase):
    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        cfg.CONF.clear()
        super(BaseExternalOauth2TokenMiddlewareTest, self).setUp()

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        self.expected_env = dict()
        self.fake_app = FakeOauth2TokenV3App
        self.middleware = None
        self.conf = {}
        self.auth_version = 'v3.0'
        self._auth_url = 'http://localhost/identity'
        self._introspect_endpoint = (
            'https://localhost:8443/realms/x509/'
            'protocol/openid-connect/token/introspect')
        self._audience = 'https://localhost:8443/realms/x509'

    def set_middleware(self, expected_env=None, conf=None):
        """Configure the class ready to call the oauth2_token middleware.

        Set up the various fake items needed to run the middleware.
        Individual tests that need to further refine these can call this
        function to override the class defaults.
        """
        if conf:
            self.conf.update(conf)

        if expected_env:
            self.expected_env.update(expected_env)
        self.middleware = external_oauth2_token.ExternalAuth2Protocol(
            self.fake_app(expected_env=self.expected_env), self.conf)

    def call(self, middleware, method='GET', path='/', headers=None,
             expected_status=HTTPStatus.OK,
             expected_body_string=None, **kwargs):
        req = webob.Request.blank(path, **kwargs)
        req.method = method

        for k, v in (headers or {}).items():
            req.headers[k] = v

        resp = req.get_response(middleware)
        self.assertEqual(expected_status, resp.status_int)
        if expected_body_string:
            self.assertIn(expected_body_string, str(resp.body))
        resp.request = req
        return resp

    def call_middleware(self,
                        pem_client_cert=None, der_client_cert=None, **kwargs):
        if pem_client_cert:
            # apache
            kwargs.update({'environ': {'SSL_CLIENT_CERT': pem_client_cert}})
        elif der_client_cert:
            # socket
            fake_socket = FakeSocket(der_client_cert)
            fake_wsgi_input = FakeWsgiInput(fake_socket)
            kwargs.update({'environ': {'wsgi.input': fake_wsgi_input}})
        return self.call(self.middleware, **kwargs)

    def _introspect_response(self, request, context,
                             auth_method=None,
                             introspect_client_id=None,
                             introspect_client_secret=None,
                             access_token=None,
                             active=True,
                             exp_time=None,
                             cert_thumb=None,
                             metadata=None,
                             status_code=200,
                             system_scope=False
                             ):
        if auth_method == 'tls_client_auth':
            body = 'client_id=%s&token=%s&token_type_hint=access_token' % (
                introspect_client_id, access_token
            )
            self.assertEqual(request.text, body)
        elif auth_method == 'client_secret_post':
            body = ('client_id=%s&client_secret=%s'
                    '&token=%s&token_type_hint=access_token') % (
                introspect_client_id, introspect_client_secret,
                access_token)
            self.assertEqual(request.text, body)
        elif auth_method == 'client_secret_basic':
            body = 'token=%s&token_type_hint=access_token' % access_token
            self.assertEqual(request.text, body)
            auth_basic = request._request.headers.get('Authorization')
            self.assertIsNotNone(auth_basic)

            auth = 'Basic ' + base64.standard_b64encode(
                ("%s:%s" % (introspect_client_id,
                            introspect_client_secret)).encode('ascii')
            ).decode('ascii')
            self.assertEqual(auth_basic, auth)
        elif auth_method == 'private_key_jwt':
            self.assertIn('client_id=%s' % introspect_client_id, request.text)
            self.assertIn(('client_assertion_type=urn%3Aietf%3Aparams%3A'
                           'oauth%3Aclient-assertion-type%3Ajwt-bearer'),
                          request.text)
            self.assertIn('client_assertion=', request.text)
            self.assertIn('token=%s' % access_token, request.text)
            self.assertIn('token_type_hint=access_token', request.text)
        elif auth_method == 'client_secret_jwt':
            self.assertIn('client_id=%s' % introspect_client_id, request.text)
            self.assertIn(('client_assertion_type=urn%3Aietf%3Aparams%3A'
                           'oauth%3Aclient-assertion-type%3Ajwt-bearer'),
                          request.text)
            self.assertIn('client_assertion=', request.text)
            self.assertIn('token=%s' % access_token, request.text)
            self.assertIn('token_type_hint=access_token', request.text)

        resp = {
            'iat': 1670311634,
            'jti': str(uuid.uuid4()),
            'iss': str(uuid.uuid4()),
            'aud': str(uuid.uuid4()),
            'sub': str(uuid.uuid4()),
            'typ': 'Bearer',
            'azp': str(uuid.uuid4()),
            'acr': '1',
            'scope': 'default'
        }
        if system_scope:
            resp['system_scope'] = 'all'

        if exp_time is not None:
            resp['exp'] = exp_time
        else:
            resp['exp'] = time.time() + 3600
        if cert_thumb is not None:
            resp['cnf'] = {
                'x5t#S256': cert_thumb
            }
        if metadata:
            for key in metadata:
                resp[key] = metadata[key]

        if active is not None:
            resp['active'] = active

        context.status_code = status_code
        return resp

    def _check_env_value_project_scope(self, request_environ,
                                       user_id, user_name,
                                       user_domain_id, user_domain_name,
                                       project_id, project_name,
                                       project_domain_id, project_domain_name,
                                       roles, is_admin=True):
        self.assertEqual('Confirmed',
                         request_environ['HTTP_X_IDENTITY_STATUS'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLES'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLE'])
        self.assertEqual(user_id, request_environ['HTTP_X_USER_ID'])
        self.assertEqual(user_name, request_environ['HTTP_X_USER_NAME'])
        self.assertEqual(user_domain_id,
                         request_environ['HTTP_X_USER_DOMAIN_ID'], )
        self.assertEqual(user_domain_name,
                         request_environ['HTTP_X_USER_DOMAIN_NAME'])
        if is_admin:
            self.assertEqual('true',
                             request_environ['HTTP_X_IS_ADMIN_PROJECT'])
        else:
            self.assertNotIn('HTTP_X_IS_ADMIN_PROJECT', request_environ)
        self.assertEqual(user_name, request_environ['HTTP_X_USER'])

        self.assertEqual(project_id, request_environ['HTTP_X_PROJECT_ID'])
        self.assertEqual(project_name, request_environ['HTTP_X_PROJECT_NAME'])
        self.assertEqual(project_domain_id,
                         request_environ['HTTP_X_PROJECT_DOMAIN_ID'])
        self.assertEqual(project_domain_name,
                         request_environ['HTTP_X_PROJECT_DOMAIN_NAME'])
        self.assertEqual(project_id, request_environ['HTTP_X_TENANT_ID'])
        self.assertEqual(project_name, request_environ['HTTP_X_TENANT_NAME'])
        self.assertEqual(project_id, request_environ['HTTP_X_TENANT'])

        self.assertNotIn('HTTP_OPENSTACK_SYSTEM_SCOPE', request_environ)
        self.assertNotIn('HTTP_X_DOMAIN_ID', request_environ)
        self.assertNotIn('HTTP_X_DOMAIN_NAME', request_environ)

    def _check_env_value_domain_scope(self, request_environ,
                                      user_id, user_name,
                                      user_domain_id, user_domain_name,
                                      domain_id, domain_name,
                                      roles, is_admin=True):
        self.assertEqual('Confirmed',
                         request_environ['HTTP_X_IDENTITY_STATUS'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLES'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLE'])
        self.assertEqual(user_id, request_environ['HTTP_X_USER_ID'])
        self.assertEqual(user_name, request_environ['HTTP_X_USER_NAME'])
        self.assertEqual(user_domain_id,
                         request_environ['HTTP_X_USER_DOMAIN_ID'], )
        self.assertEqual(user_domain_name,
                         request_environ['HTTP_X_USER_DOMAIN_NAME'])
        if is_admin:
            self.assertEqual('true',
                             request_environ['HTTP_X_IS_ADMIN_PROJECT'])
        else:
            self.assertNotIn('HTTP_X_IS_ADMIN_PROJECT', request_environ)
        self.assertEqual(user_name, request_environ['HTTP_X_USER'])

        self.assertEqual(domain_id, request_environ['HTTP_X_DOMAIN_ID'])
        self.assertEqual(domain_name, request_environ['HTTP_X_DOMAIN_NAME'])
        self.assertNotIn('HTTP_OPENSTACK_SYSTEM_SCOPE', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_ID', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_NAME', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_DOMAIN_ID', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_DOMAIN_NAME', request_environ)
        self.assertNotIn('HTTP_X_TENANT_ID', request_environ)
        self.assertNotIn('HTTP_X_TENANT_NAME', request_environ)
        self.assertNotIn('HTTP_X_TENANT', request_environ)

    def _check_env_value_system_scope(self, request_environ,
                                      user_id, user_name,
                                      user_domain_id, user_domain_name,
                                      roles, is_admin=True, system_scope=True):
        self.assertEqual('Confirmed',
                         request_environ['HTTP_X_IDENTITY_STATUS'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLES'])
        self.assertEqual(roles, request_environ['HTTP_X_ROLE'])

        self.assertEqual(user_id, request_environ['HTTP_X_USER_ID'])
        self.assertEqual(user_name, request_environ['HTTP_X_USER_NAME'])
        self.assertEqual(user_domain_id,
                         request_environ['HTTP_X_USER_DOMAIN_ID'], )
        self.assertEqual(user_domain_name,
                         request_environ['HTTP_X_USER_DOMAIN_NAME'])
        if is_admin:
            self.assertEqual('true',
                             request_environ['HTTP_X_IS_ADMIN_PROJECT'])
        else:
            self.assertNotIn('HTTP_X_IS_ADMIN_PROJECT', request_environ)
        self.assertEqual(user_name, request_environ['HTTP_X_USER'])
        self.assertEqual('all', request_environ['HTTP_OPENSTACK_SYSTEM_SCOPE'])

        self.assertNotIn('HTTP_X_DOMAIN_ID', request_environ)
        self.assertNotIn('HTTP_X_DOMAIN_NAME', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_ID', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_NAME', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_DOMAIN_ID', request_environ)
        self.assertNotIn('HTTP_X_PROJECT_DOMAIN_NAME', request_environ)
        self.assertNotIn('HTTP_X_TENANT_ID', request_environ)
        self.assertNotIn('HTTP_X_TENANT_NAME', request_environ)
        self.assertNotIn('HTTP_X_TENANT', request_environ)


class ExternalOauth2TokenMiddlewareTlsClientAuthTest(
        BaseExternalOauth2TokenMiddlewareTest):
    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(ExternalOauth2TokenMiddlewareTlsClientAuthTest, self).setUp()

        self._test_client_id = str(uuid.uuid4())
        self._auth_method = 'tls_client_auth'
        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            thumbprint_verify=True,
            mapping_project_id='access_project.id',
            mapping_project_name='access_project.name',
            mapping_project_domain_id='access_project.domain.id',
            mapping_project_domain_name='access_project.domain.name',
            mapping_user_id='client_id',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
        )
        self._token = str(uuid.uuid4()) + '_user_token'
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'access_project': {
                'id': self._project_id,
                'name': self._project_name,
                'domain': {
                    'id': self._project_domain_id,
                    'name': self._project_domain_name
                }
            },
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'client_id': self._user_id,
            'username': self._user_name,
        }
        cert = self.examples.V3_OAUTH2_MTLS_CERTIFICATE
        self._pem_client_cert = cert.decode('ascii')
        self._der_client_cert = ssl.PEM_cert_to_DER_cert(self._pem_client_cert)
        thumb_sha256 = hashlib.sha256(self._der_client_cert).digest()
        self._cert_thumb = jwt.utils.base64url_encode(thumb_sha256).decode(
            'ascii')

    def test_basic_200(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertEqual(resp.request.environ['HTTP_X_IDENTITY_STATUS'],
                         'Confirmed')
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    def test_thumbprint_verify_is_false_200(self):
        conf = copy.deepcopy(self._test_conf)
        conf['thumbprint_verify'] = False
        self.set_middleware(conf=conf)

        metadata = copy.deepcopy(self._default_metadata)
        metadata['access_project'].pop('id')
        roles = 'reader'
        metadata['roles'] = roles

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb='this is an incorrectly thumbprint.',
                metadata=metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertEqual(resp.request.environ['HTTP_X_IDENTITY_STATUS'],
                         'Confirmed')
        self._check_env_value_domain_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_domain_id, self._project_domain_name, roles,
            is_admin=False)

    def test_confirm_certificate_thumbprint_get_socket_except_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': {'test': 'test'}}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_socket_is_none_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(None)}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_peercert_is_none_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_peercert_error_format_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket('Error Format'))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_wsgi_input_is_none_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': None}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_is_not_match_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb='NotMatchThumbprint',
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_confirm_certificate_thumbprint_apache_default_200(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            pem_client_cert=self._pem_client_cert
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self.assertEqual(resp.request.environ['HTTP_X_IDENTITY_STATUS'],
                         'Confirmed')
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    def test_confirm_certificate_thumbprint_pem_der_none_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                access_token=self._token,
                active=True,
                cert_thumb=self._cert_thumb,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            pem_client_cert=None,
            der_client_cert=None
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)


class ExternalOauth2TokenMiddlewarePrivateJWTKeyTest(
        BaseExternalOauth2TokenMiddlewareTest):

    def setUp(self):
        super(ExternalOauth2TokenMiddlewarePrivateJWTKeyTest, self).setUp()

        self._test_client_id = str(uuid.uuid4())
        self._test_client_secret = str(uuid.uuid4())
        self._jwt_key_file = '/root/key.pem'
        self._auth_method = 'private_key_jwt'
        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            client_secret=self._test_client_secret,
            jwt_key_file=self._jwt_key_file,
            jwt_algorithm='RS256',
            jwt_bearer_time_out='2800',
            mapping_project_id='access_project.id',
            mapping_project_name='access_project.name',
            mapping_project_domain_id='access_project.domain.id',
            mapping_project_domain_name='access_project.domain.name',
            mapping_user_id='client_id',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
        )
        self._token = str(uuid.uuid4()) + '_user_token'
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'access_project': {
                'id': self._project_id,
                'name': self._project_name,
                'domain': {
                    'id': self._project_domain_id,
                    'name': self._project_domain_name
                }
            },
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'client_id': self._user_id,
            'username': self._user_name,
        }

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', mock.mock_open(read_data=JWT_KEY_CONTENT))
    def test_basic_200(self, mocker_path_isfile):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        def mocker_isfile_side_effect(filename):
            if filename == self._jwt_key_file:
                return True
            else:
                return False

        mocker_path_isfile.side_effect = mocker_isfile_side_effect

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertTrue(mocker_path_isfile.called)
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', mock.mock_open(read_data=JWT_KEY_CONTENT))
    def test_introspect_by_private_key_jwt_error_alg_500(
            self, mocker_path_isfile):
        conf = copy.deepcopy(self._test_conf)
        conf['jwt_algorithm'] = 'HS256'
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        def mocker_isfile_side_effect(filename):
            if filename == self._jwt_key_file:
                return True
            else:
                return False

        mocker_path_isfile.side_effect = mocker_isfile_side_effect

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    @mock.patch('os.path.isfile')
    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    def test_introspect_by_private_key_jwt_error_file_no_content_500(
            self, mocker_path_isfile):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        def mocker_isfile_side_effect(filename):
            if filename == self._jwt_key_file:
                return True
            else:
                return False

        mocker_path_isfile.side_effect = mocker_isfile_side_effect

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    @mock.patch('os.path.isfile')
    def test_introspect_by_private_key_jwt_error_file_can_not_read_500(
            self, mocker_path_isfile):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        def mocker_isfile_side_effect(filename):
            if filename == self._jwt_key_file:
                return True
            else:
                return False

        mocker_path_isfile.side_effect = mocker_isfile_side_effect

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_introspect_by_private_key_jwt_error_file_not_exist_500(
            self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)
        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )


class ExternalOauth2TokenMiddlewareClientSecretJWTTest(
        BaseExternalOauth2TokenMiddlewareTest):

    def setUp(self):
        super(ExternalOauth2TokenMiddlewareClientSecretJWTTest, self).setUp()

        self._test_client_id = str(uuid.uuid4())
        self._test_client_secret = str(uuid.uuid4())
        self._auth_method = 'client_secret_jwt'
        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            client_secret=self._test_client_secret,
            jwt_key_file='test',
            jwt_algorithm='HS256',
            jwt_bearer_time_out='2800',
            mapping_project_id='access_project.id',
            mapping_project_name='access_project.name',
            mapping_project_domain_id='access_project.domain.id',
            mapping_project_domain_name='access_project.domain.name',
            mapping_user_id='client_id',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
        )
        self._token = str(uuid.uuid4()) + '_user_token'
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'access_project': {
                'id': self._project_id,
                'name': self._project_name,
                'domain': {
                    'id': self._project_domain_id,
                    'name': self._project_domain_name
                }
            },
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'client_id': self._user_id,
            'username': self._user_name,
        }

    def test_basic_200(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    def test_introspect_by_client_secret_jwt_error_alg_500(self):
        conf = copy.deepcopy(self._test_conf)
        conf['jwt_algorithm'] = 'RS256'
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_fetch_token_introspect_response_201_500(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata,
                status_code=201
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_fetch_token_introspect_response_active_is_false_401(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=False,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp,
                                status_code=500)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)

    def test_fetch_token_introspect_response_500(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata,
                status_code=500
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    @mock.patch.object(session.Session, 'request')
    def test_fetch_token_introspect_timeout_500(self, mock_session_request):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        mock_session_request.side_effect = ksa_exceptions.RequestTimeout(
            'time out')
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )


class ExternalOauth2TokenMiddlewareClientSecretPostTest(
        BaseExternalOauth2TokenMiddlewareTest):

    def setUp(self):
        super(ExternalOauth2TokenMiddlewareClientSecretPostTest, self).setUp()

        self._test_client_id = str(uuid.uuid4())
        self._test_client_secret = str(uuid.uuid4())
        self._auth_method = 'client_secret_post'
        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            client_secret=self._test_client_secret,
            thumbprint_verify=False,
            mapping_project_id='project_id',
            mapping_project_name='project_name',
            mapping_project_domain_id='domain_id',
            mapping_project_domain_name='domain_name',
            mapping_user_id='user',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
        )
        self._token = str(uuid.uuid4()) + '_user_token'
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'project_id': self._project_id,
            'project_name': self._project_name,
            'domain_id': self._project_domain_id,
            'domain_name': self._project_domain_name,
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'user': self._user_id,
            'username': self._user_name,
        }

    def test_basic_200(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    def test_process_request_no_access_token_in_header_401(self):
        conf = copy.deepcopy(self._test_conf)
        test_audience = 'https://test_audience'
        conf['audience'] = test_audience
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers={},
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % test_audience)

    def test_read_data_from_token_key_type_not_dict_403(self):
        conf = copy.deepcopy(self._test_conf)
        conf['mapping_user_id'] = 'user.id'
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=403,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_read_data_from_token_key_not_fount_in_metadata_403(self):
        conf = copy.deepcopy(self._test_conf)
        conf['mapping_user_id'] = 'user_id'
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=403,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_read_data_from_token_key_value_type_is_not_match_403(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        metadata = copy.deepcopy(self._default_metadata)
        metadata['user'] = {
            'id': str(uuid.uuid4()),
            'name': 'testName'
        }

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=403,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_read_data_from_token_key_config_error_is_not_dict_500(self):
        conf = copy.deepcopy(self._test_conf)
        conf['mapping_project_id'] = '..project_id'
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_read_data_from_token_key_config_error_is_not_set_500(self):
        conf = copy.deepcopy(self._test_conf)
        conf.pop('mapping_roles')
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )


class ExternalOauth2TokenMiddlewareClientSecretBasicTest(
        BaseExternalOauth2TokenMiddlewareTest):

    def setUp(self):
        super(ExternalOauth2TokenMiddlewareClientSecretBasicTest, self).setUp()

        self._test_client_id = str(uuid.uuid4())
        self._test_client_secret = str(uuid.uuid4())
        self._auth_method = 'client_secret_basic'
        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            client_secret=self._test_client_secret,
            thumbprint_verify=False,
            mapping_project_id='access_project.id',
            mapping_project_name='access_project.name',
            mapping_project_domain_id='access_project.domain.id',
            mapping_project_domain_name='access_project.domain.name',
            mapping_user_id='client_id',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
        )
        self._token = str(uuid.uuid4()) + '_user_token'
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'access_project': {
                'id': self._project_id,
                'name': self._project_name,
                'domain': {
                    'id': self._project_domain_id,
                    'name': self._project_domain_name
                }
            },
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'client_id': self._user_id,
            'username': self._user_name,
        }
        self._clear_call_count = 0

    def test_basic_200(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_project_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_id, self._project_name, self._project_domain_id,
            self._project_domain_name, self._roles)

    def test_domain_scope_200(self):
        conf = copy.deepcopy(self._test_conf)
        conf.pop('mapping_project_id')
        self.set_middleware(conf=conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_domain_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name,
            self._project_domain_id, self._project_domain_name, self._roles)

    def test_system_scope_200(self):
        conf = copy.deepcopy(self._test_conf)
        conf.pop('mapping_project_id')
        conf['mapping_system_scope'] = "system.all"
        self.set_middleware(conf=conf)
        self._default_metadata["system"] = {"all": True}

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata,
                system_scope=True
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        self._check_env_value_system_scope(
            resp.request.environ, self._user_id, self._user_name,
            self._user_domain_id, self._user_domain_name, self._roles)

    def test_process_response_401(self):
        conf = copy.deepcopy(self._test_conf)
        conf.pop('mapping_project_id')
        self.set_middleware(conf=conf)
        self.middleware = external_oauth2_token.ExternalAuth2Protocol(
            FakeOauth2TokenV3App(expected_env=self.expected_env,
                                 app_response_status_code=401), self.conf)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        resp = self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertEqual(resp.headers.get('WWW-Authenticate'),
                         'Authorization OAuth 2.0 uri="%s"' % self._audience)


class ExternalAuth2ProtocolTest(BaseExternalOauth2TokenMiddlewareTest):

    def setUp(self):
        super(ExternalAuth2ProtocolTest, self).setUp()
        self._test_client_id = str(uuid.uuid4())
        self._test_client_secret = str(uuid.uuid4())
        self._auth_method = 'client_secret_basic'

        self._test_conf = get_config(
            introspect_endpoint=self._introspect_endpoint,
            audience=self._audience,
            auth_method=self._auth_method,
            client_id=self._test_client_id,
            client_secret=self._test_client_secret,
            thumbprint_verify=False,
            mapping_project_id='access_project.id',
            mapping_project_name='access_project.name',
            mapping_project_domain_id='access_project.domain.id',
            mapping_project_domain_name='access_project.domain.name',
            mapping_user_id='client_id',
            mapping_user_name='username',
            mapping_user_domain_id='user_domain.id',
            mapping_user_domain_name='user_domain.name',
            mapping_roles='roles',
            mapping_system_scope='system.all',
            mapping_expires_at='exp',
            memcached_servers=','.join(MEMCACHED_SERVERS),
            memcache_use_advanced_pool=True,
            memcache_pool_dead_retry=300,
            memcache_pool_maxsize=10,
            memcache_pool_unused_timeout=60,
            memcache_pool_conn_get_timeout=10,
            memcache_pool_socket_timeout=3,
            memcache_security_strategy=None,
            memcache_secret_key=None
        )
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
        self._token = self.token_dict['uuid_token_default']
        self._user_id = str(uuid.uuid4()) + '_user_id'
        self._user_name = str(uuid.uuid4()) + '_user_name'
        self._user_domain_id = str(uuid.uuid4()) + '_user_domain_id'
        self._user_domain_name = str(uuid.uuid4()) + '_user_domain_name'
        self._project_id = str(uuid.uuid4()) + '_project_id'
        self._project_name = str(uuid.uuid4()) + '_project_name'
        self._project_domain_id = str(uuid.uuid4()) + 'project_domain_id'
        self._project_domain_name = str(uuid.uuid4()) + 'project_domain_name'
        self._roles = 'admin,member,reader'

        self._default_metadata = {
            'access_project': {
                'id': self._project_id,
                'name': self._project_name,
                'domain': {
                    'id': self._project_domain_id,
                    'name': self._project_domain_name
                }
            },
            'user_domain': {
                'id': self._user_domain_id,
                'name': self._user_domain_name
            },
            'roles': self._roles,
            'client_id': self._user_id,
            'username': self._user_name,
            'exp': int(time.time()) + 3600
        }
        self._clear_call_count = 0
        cert = self.examples.V3_OAUTH2_MTLS_CERTIFICATE
        self._pem_client_cert = cert.decode('ascii')
        self._der_client_cert = ssl.PEM_cert_to_DER_cert(self._pem_client_cert)
        thumb_sha256 = hashlib.sha256(self._der_client_cert).digest()
        self._cert_thumb = jwt.utils.base64url_encode(thumb_sha256).decode(
            'ascii')

    def test_token_cache_factory_insecure(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.assertIsInstance(self.middleware._token_cache, _cache.TokenCache)

    def test_token_cache_factory_secure(self):
        conf = copy.deepcopy(self._test_conf)
        conf["memcache_secret_key"] = "test_key"
        conf["memcache_security_strategy"] = "MAC"
        self.set_middleware(conf=conf)
        self.assertIsInstance(self.middleware._token_cache,
                              _cache.SecureTokenCache)
        conf["memcache_security_strategy"] = "ENCRYPT"
        self.set_middleware(conf=conf)
        self.assertIsInstance(self.middleware._token_cache,
                              _cache.SecureTokenCache)

    def test_caching_token_on_verify(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = _cache._FakeClient()
        self.middleware._token_cache.initialize(env={'cache': cache})
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertThat(1, matchers.Equals(cache.set.call_count))

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        # Assert that the token wasn't cached again.
        self.assertThat(1, matchers.Equals(cache.set.call_count))

    def test_caching_token_timeout(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = _cache._FakeClient()
        self.middleware._token_cache.initialize(env={'cache': cache})
        self._default_metadata['exp'] = int(time.time()) - 3600
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertThat(1, matchers.Equals(cache.set.call_count))
        # Confirm that authentication fails due to timeout.
        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    @mock.patch('keystonemiddleware.auth_token._cache.TokenCache.get')
    def test_caching_token_type_invalid(self, mock_cache_get):
        mock_cache_get.return_value = "test"
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = _cache._FakeClient()
        self.middleware._token_cache.initialize(env={'cache': cache})
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )

    def test_caching_token_not_active(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = _cache._FakeClient()
        self.middleware._token_cache.initialize(env={'cache': cache})
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=False,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertThat(1, matchers.Equals(cache.set.call_count))

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        # Assert that the token wasn't cached again.
        self.assertThat(1, matchers.Equals(cache.set.call_count))

    def test_caching_token_invalid(self):
        conf = copy.deepcopy(self._test_conf)
        self.set_middleware(conf=conf)
        self.middleware._token_cache._env_cache_name = 'cache'
        cache = _cache._FakeClient()
        self.middleware._token_cache.initialize(env={'cache': cache})
        orig_cache_set = cache.set
        cache.set = mock.Mock(side_effect=orig_cache_set)

        def mock_resp(request, context):
            return self._introspect_response(
                request, context,
                auth_method=self._auth_method,
                introspect_client_id=self._test_client_id,
                introspect_client_secret=self._test_client_secret,
                access_token=self._token,
                active=True,
                metadata=self._default_metadata
            )

        self.requests_mock.post(self._introspect_endpoint,
                                json=mock_resp)
        self.requests_mock.get(self._auth_url,
                               json=VERSION_LIST_v3,
                               status_code=300)

        self.call_middleware(
            headers=get_authorization_header(self._token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertThat(1, matchers.Equals(cache.set.call_count))
        # Confirm that authentication fails due to invalid token.
        self.call_middleware(
            headers=get_authorization_header(str(uuid.uuid4()) + '_token'),
            expected_status=500,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            der_client_cert=self._der_client_cert,
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self._token = self.token_dict['uuid_token_default']


class FilterFactoryTest(utils.BaseTestCase):

    def test_filter_factory(self):
        certfile = '/certfile_01'
        keyfile = '/keyfile_01'
        cafile = '/cafile_01'
        insecure = True
        http_connect_timeout = 1000
        introspect_endpoint = 'http://introspect_endpoint_01'
        audience = 'http://audience_01'
        auth_method = 'private_key_jwt'
        client_id = 'client_id_01'
        client_secret = 'client_secret_01'
        thumbprint_verify = True
        jwt_key_file = '/jwt_key_file_01'
        jwt_algorithm = 'HS512'
        jwt_bearer_time_out = 1000
        mapping_project_id = 'test_project.id'
        mapping_project_name = 'test_project.name'
        mapping_project_domain_id = 'test_project.domain.id'
        mapping_project_domain_name = 'test_project.domain.name'
        mapping_user_id = 'test_client_id'
        mapping_user_name = 'test_username'
        mapping_user_domain_id = 'test_user_domain.id'
        mapping_user_domain_name = 'test_user_domain.name'
        mapping_roles = 'test_roles'

        conf = {
            'certfile': certfile,
            'keyfile': keyfile,
            'cafile': cafile,
            'insecure': insecure,
            'http_connect_timeout': http_connect_timeout,
            'introspect_endpoint': introspect_endpoint,
            'audience': audience,
            'auth_method': auth_method,
            'client_id': client_id,
            'client_secret': client_secret,
            'thumbprint_verify': thumbprint_verify,
            'jwt_key_file': jwt_key_file,
            'jwt_algorithm': jwt_algorithm,
            'jwt_bearer_time_out': jwt_bearer_time_out,
            'mapping_project_id': mapping_project_id,
            'mapping_project_name': mapping_project_name,
            'mapping_project_domain_id': mapping_project_domain_id,
            'mapping_project_domain_name': mapping_project_domain_name,
            'mapping_user_id': mapping_user_id,
            'mapping_user_name': mapping_user_name,
            'mapping_user_domain_id': mapping_user_domain_id,
            'mapping_user_domain_name': mapping_user_domain_name,
            'mapping_roles': mapping_roles
        }
        auth_filter = external_oauth2_token.filter_factory(conf)
        app = FakeApp()
        m = auth_filter(app)
        self.assertIsInstance(m, external_oauth2_token.ExternalAuth2Protocol)

        self.assertEqual(certfile,
                         m._get_config_option('certfile', is_required=False))
        self.assertEqual(keyfile,
                         m._get_config_option('keyfile', is_required=False))
        self.assertEqual(cafile,
                         m._get_config_option('cafile', is_required=False))
        self.assertEqual(insecure,
                         m._get_config_option('insecure', is_required=False))
        self.assertEqual(http_connect_timeout,
                         m._get_config_option('http_connect_timeout',
                                              is_required=False))
        self.assertEqual(introspect_endpoint,
                         m._get_config_option('introspect_endpoint',
                                              is_required=False))
        self.assertEqual(audience,
                         m._get_config_option('audience', is_required=False))
        self.assertEqual(auth_method, m._get_config_option('auth_method',
                                                           is_required=False))
        self.assertEqual(client_id,
                         m._get_config_option('client_id', is_required=False))
        self.assertEqual(client_secret,
                         m._get_config_option('client_secret',
                                              is_required=False))
        self.assertEqual(thumbprint_verify,
                         m._get_config_option('thumbprint_verify',
                                              is_required=False))
        self.assertEqual(jwt_key_file, m._get_config_option('jwt_key_file',
                                                            is_required=False))
        self.assertEqual(jwt_algorithm,
                         m._get_config_option('jwt_algorithm',
                                              is_required=False))
        self.assertEqual(jwt_bearer_time_out,
                         m._get_config_option('jwt_bearer_time_out',
                                              is_required=False))
        self.assertEqual(mapping_project_id,
                         m._get_config_option('mapping_project_id',
                                              is_required=False))
        self.assertEqual(mapping_project_name,
                         m._get_config_option('mapping_project_name',
                                              is_required=False))
        self.assertEqual(mapping_project_domain_id,
                         m._get_config_option('mapping_project_domain_id',
                                              is_required=False))
        self.assertEqual(mapping_project_domain_name,
                         m._get_config_option('mapping_project_domain_name',
                                              is_required=False))
        self.assertEqual(mapping_user_id,
                         m._get_config_option('mapping_user_id',
                                              is_required=False))
        self.assertEqual(mapping_user_name,
                         m._get_config_option('mapping_user_name',
                                              is_required=False))
        self.assertEqual(mapping_user_domain_id,
                         m._get_config_option('mapping_user_domain_id',
                                              is_required=False))
        self.assertEqual(mapping_user_domain_name,
                         m._get_config_option('mapping_user_domain_name',
                                              is_required=False))
        self.assertEqual(mapping_roles,
                         m._get_config_option('mapping_roles',
                                              is_required=False))
