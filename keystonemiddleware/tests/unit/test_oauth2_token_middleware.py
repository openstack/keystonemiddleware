# Copyright 2022 OpenStack Foundation
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

import fixtures
import http.client as http_client
import logging
import testresources
import uuid
import webob.dec

from oslo_config import cfg

from keystoneauth1 import exceptions as ksa_exceptions

from keystonemiddleware import oauth2_token
from keystonemiddleware.tests.unit.auth_token import base
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import BASE_URI
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import ENDPOINT_NOT_FOUND_TOKEN
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import ERROR_TOKEN
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FAKE_ADMIN_TOKEN
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FAKE_ADMIN_TOKEN_ID
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware\
    import FakeApp
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FakeOsloCache
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import request_timeout_response
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import TIMEOUT_TOKEN
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import v3FakeApp
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import VERSION_LIST_v3
from keystonemiddleware.tests.unit import client_fixtures
from keystonemiddleware.tests.unit import utils


def get_authorization_header(token):
    return {'Authorization': f'Bearer {token}'}


class FakeOauth2TokenV3App(v3FakeApp):

    @webob.dec.wsgify
    def __call__(self, req):
        resp = webob.Response()
        resp.body = FakeApp.SUCCESS
        return resp


class BaseOauth2TokenMiddlewareTest(base.BaseAuthTokenTestCase):

    def setUp(self, expected_env=None, auth_version=None, fake_app=None):
        cfg.CONF.clear()
        super(BaseOauth2TokenMiddlewareTest, self).setUp()

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        self.useFixture(fixtures.MockPatchObject(oauth2_token.OAuth2Protocol,
                                                 '_create_oslo_cache',
                                                 return_value=FakeOsloCache))
        self.expected_env = expected_env or dict()
        self.fake_app = fake_app or FakeApp
        self.middleware = None

        self.conf = {
            'identity_uri': 'https://keystone.example.com:1234/testadmin/',
            'auth_version': auth_version,
            'www_authenticate_uri': 'https://keystone.example.com:1234',
            'admin_user': uuid.uuid4().hex,
        }
        self.auth_version = auth_version

    def call_middleware(self, **kwargs):
        return self.call(self.middleware, **kwargs)

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
        self.middleware = oauth2_token.OAuth2Protocol(
            self.fake_app(self.expected_env), self.conf)

    def call(self, middleware, method='GET', path='/', headers=None,
             expected_status=http_client.OK,
             expected_body_string=None):
        req = webob.Request.blank(path)
        req.method = method

        for k, v in (headers or {}).items():
            req.headers[k] = v

        resp = req.get_response(middleware)
        self.assertEqual(expected_status, resp.status_int)
        if expected_body_string:
            self.assertIn(expected_body_string, str(resp.body))
        resp.request = req
        return resp


class Oauth2TokenMiddlewareTest(BaseOauth2TokenMiddlewareTest,
                                testresources.ResourcedTestCase):

    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(Oauth2TokenMiddlewareTest, self).setUp(
            auth_version='v3.0',
            fake_app=FakeOauth2TokenV3App)
        self.requests_mock.post('%s/v2.0/tokens' % BASE_URI,
                                text=FAKE_ADMIN_TOKEN)
        self.requests_mock.get(BASE_URI,
                               json=VERSION_LIST_v3,
                               status_code=300)
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
        if token_id == ENDPOINT_NOT_FOUND_TOKEN:
            raise ksa_exceptions.EndpointNotFound()
        if token_id == TIMEOUT_TOKEN:
            request_timeout_response(request, context)

        try:
            response = self.examples.JSON_TOKEN_RESPONSES[token_id]
        except KeyError:
            response = ""
            context.status_code = 404

        return response

    def test_app_cred_token_without_access_rules(self):
        self.set_middleware(conf={'service_type': 'compute'})
        token = self.examples.v3_APP_CRED_TOKEN
        token_data = self.examples.TOKEN_RESPONSES[token]
        resp = self.call_middleware(headers=get_authorization_header(token))
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        token_auth = resp.request.environ['keystone.token_auth']
        self.assertEqual(token_data.application_credential_id,
                         token_auth.user.application_credential_id)

    def test_app_cred_access_rules_token(self):
        self.set_middleware(conf={'service_type': 'compute'})
        token = self.examples.v3_APP_CRED_ACCESS_RULES
        token_data = self.examples.TOKEN_RESPONSES[token]
        resp = self.call_middleware(headers=get_authorization_header(token),
                                    expected_status=200,
                                    method='GET', path='/v2.1/servers')
        token_auth = resp.request.environ['keystone.token_auth']
        self.assertEqual(token_data.application_credential_id,
                         token_auth.user.application_credential_id)
        self.assertEqual(token_data.application_credential_access_rules,
                         token_auth.user.application_credential_access_rules)
        resp = self.call_middleware(headers=get_authorization_header(token),
                                    expected_status=401,
                                    method='GET',
                                    path='/v2.1/servers/someuuid')
        self.assertEqual(token_data.application_credential_id,
                         token_auth.user.application_credential_id)
        self.assertEqual(token_data.application_credential_access_rules,
                         token_auth.user.application_credential_access_rules)

    def test_app_cred_no_access_rules_token(self):
        self.set_middleware(conf={'service_type': 'compute'})
        token = self.examples.v3_APP_CRED_EMPTY_ACCESS_RULES
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v2.1/servers')

    def test_app_cred_matching_rules(self):
        self.set_middleware(conf={'service_type': 'compute'})
        token = self.examples.v3_APP_CRED_MATCHING_RULES
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=200,
                             method='GET', path='/v2.1/servers/foobar')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v2.1/servers/foobar/barfoo')
        self.set_middleware(conf={'service_type': 'image'})
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=200,
                             method='GET', path='/v2/images/foobar')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v2/images/foobar/barfoo')
        self.set_middleware(conf={'service_type': 'identity'})
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=200,
                             method='GET',
                             path='/v3/projects/123/users/456/roles/member')
        self.set_middleware(conf={'service_type': 'block-storage'})
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=200,
                             method='GET', path='/v3/123/types/456')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v3/123/types')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v2/123/types/456')
        self.set_middleware(conf={'service_type': 'object-store'})
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=200,
                             method='GET', path='/v1/1/2/3')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v1/1/2')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/v2/1/2')
        self.call_middleware(headers=get_authorization_header(token),
                             expected_status=401,
                             method='GET', path='/info')

    def test_request_no_token(self):
        resp = self.call_middleware(expected_status=401)
        self.assertEqual('Keystone uri="https://keystone.example.com:1234"',
                         resp.headers['WWW-Authenticate'])

    def test_request_blank_token(self):
        resp = self.call_middleware(headers=get_authorization_header(''),
                                    expected_status=401)
        self.assertEqual('Keystone uri="https://keystone.example.com:1234"',
                         resp.headers['WWW-Authenticate'])

    def test_request_not_app_cred_token(self):
        self.call_middleware(
            headers=get_authorization_header(
                self.examples.v3_UUID_TOKEN_DEFAULT),
            expected_status=200)

    def _get_cached_token(self, token):
        return self.middleware._token_cache.get(token)

    def assert_valid_last_url(self, token_id):
        self.assertLastPath('/v3/auth/tokens')

    def assertLastPath(self, path):
        if path:
            self.assertEqual(BASE_URI + path,
                             self.requests_mock.last_request.url)
        else:
            self.assertIsNone(self.requests_mock.last_request)

    def test_http_error_not_cached_token(self):
        """Test to don't cache token as invalid on network errors.

        We use UUID tokens since they are the easiest one to reach
        get_http_connection.
        """
        self.set_middleware(conf={'http_request_max_retries': '0'})
        self.call_middleware(headers=get_authorization_header(ERROR_TOKEN),
                             expected_status=503)
        self.assertIsNone(self._get_cached_token(ERROR_TOKEN))
        self.assert_valid_last_url(ERROR_TOKEN)


class FilterFactoryTest(utils.BaseTestCase):

    def test_filter_factory(self):
        conf = {}
        auth_filter = oauth2_token.filter_factory(conf)
        m = auth_filter(FakeOauth2TokenV3App())
        self.assertIsInstance(m, oauth2_token.OAuth2Protocol)
