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

import http.client as http_client
import json
import logging
import ssl
from unittest import mock
import uuid
import webob.dec

import fixtures
from oslo_config import cfg
import testresources

from keystoneauth1 import access
from keystoneauth1 import exceptions as ksa_exceptions

from keystonemiddleware import oauth2_mtls_token
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
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FakeApp
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FakeOsloCache
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import request_timeout_response
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import TIMEOUT_TOKEN
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import VERSION_LIST_v3
from keystonemiddleware.tests.unit import client_fixtures
from keystonemiddleware.tests.unit.test_oauth2_token_middleware \
    import FakeOauth2TokenV3App
from keystonemiddleware.tests.unit.test_oauth2_token_middleware \
    import get_authorization_header
from keystonemiddleware.tests.unit import utils

_no_value = object()


class FakeSocket(object):

    def __init__(self, binary_peer_cert):
        self.binary_peer_cert = binary_peer_cert

    def getpeercert(self, binary_form=True):
        return self.binary_peer_cert


class FakeWsgiInput(object):

    def __init__(self, fake_socket):
        self.fake_socket = fake_socket

    def get_socket(self):
        return self.fake_socket


class BaseOauth2mTlsTokenMiddlewareTest(base.BaseAuthTokenTestCase):

    def setUp(self, expected_env=None, auth_version=None, fake_app=None):
        cfg.CONF.clear()
        super(BaseOauth2mTlsTokenMiddlewareTest, self).setUp()

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        self.useFixture(
            fixtures.MockPatchObject(oauth2_mtls_token.OAuth2mTlsProtocol,
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
        self.middleware = oauth2_mtls_token.OAuth2mTlsProtocol(
            self.fake_app(self.expected_env), self.conf)

    def call(self, middleware, method='GET', path='/', headers=None,
             expected_status=http_client.OK,
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

    def assertUnauthorizedResp(self, resp):
        error = json.loads(resp.body)

        self.assertEqual('Keystone uri="https://keystone.example.com:1234"',
                         resp.headers['WWW-Authenticate'])
        self.assertEqual(
            'Keystone uri="%s"' % self.conf.get('www_authenticate_uri'),
            resp.headers['WWW-Authenticate'])
        self.assertEqual(
            'Unauthorized',
            error.get('error').get('title'))
        self.assertEqual(
            'The request you have made requires authentication.',
            error.get('error').get('message'))


class Oauth2mTlsTokenMiddlewareTest(BaseOauth2mTlsTokenMiddlewareTest,
                                    testresources.ResourcedTestCase):
    resources = [('examples', client_fixtures.EXAMPLES_RESOURCE)]

    def setUp(self):
        super(Oauth2mTlsTokenMiddlewareTest, self).setUp(
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
        self.set_middleware(conf={'service_type': 'tacker'})

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

    def call_middleware(self, client_cert=_no_value, **kwargs):
        if client_cert is _no_value:
            client_cert = self.examples.V3_OAUTH2_MTLS_CERTIFICATE

        if client_cert:
            fake_socket = FakeSocket(client_cert)
            fake_wsgi_input = FakeWsgiInput(fake_socket)
            kwargs.update({'environ': {'wsgi.input': fake_wsgi_input}})

        return self.call(self.middleware, **kwargs)

    def test_basic(self):
        token = self.examples.v3_OAUTH2_CREDENTIAL
        token_data = self.examples.TOKEN_RESPONSES[token]

        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=200,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
        )
        self.assertEqual(FakeApp.SUCCESS, resp.body)
        token_auth = resp.request.environ['keystone.token_auth']
        self.assertTrue(token_auth.has_user_token)
        self.assertEqual(token_data.user_id, token_auth.user.user_id)
        self.assertEqual(token_data.project_id, token_auth.user.project_id)
        self.assertEqual(token_data.user_domain_id,
                         token_auth.user.user_domain_id)
        self.assertEqual(token_data.project_domain_id,
                         token_auth.user.project_domain_id)
        self.assertEqual(token_data.oauth2_thumbprint,
                         token_auth.user.oauth2_credential_thumbprint)

    def test_not_oauth2_credential_token(self):
        token = self.examples.v3_APP_CRED_TOKEN
        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn(
            'Invalid OAuth2.0 certificate-bound access token: '
            'The token is not an OAuth2.0 credential access token.',
            self.logger.output)

    def test_thumbprint_not_match(self):
        diff_cert = self.examples.V3_OAUTH2_MTLS_CERTIFICATE_DIFF
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            client_cert=diff_cert
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn('The two thumbprints do not match.',
                      self.logger.output)

    @mock.patch.object(ssl, 'DER_cert_to_PEM_cert')
    def test_gen_thumbprint_exception(self, mock_DER_cert_to_PEM_cert):
        except_msg = 'Boom!'
        mock_DER_cert_to_PEM_cert.side_effect = Exception(except_msg)
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages'
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn(except_msg, self.logger.output)

    def test_without_cert(self):
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            client_cert=None
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn('Unable to obtain the client certificate.',
                      self.logger.output)

    def test_not_wsgi_input(self):
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = super(Oauth2mTlsTokenMiddlewareTest, self).call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': None}
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn('Unable to obtain the client certificate.',
                      self.logger.output)

    def test_not_socket(self):
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = super(Oauth2mTlsTokenMiddlewareTest, self).call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(None)}
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn('Unable to obtain the client certificate.',
                      self.logger.output)

    def test_not_peer_cert(self):
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = super(Oauth2mTlsTokenMiddlewareTest, self).call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
            environ={'wsgi.input': FakeWsgiInput(FakeSocket(None))}
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn('Unable to obtain the client certificate.',
                      self.logger.output)

    @mock.patch.object(access, 'create')
    def test_keystonemiddleware_exceptiton(self, mock_create):
        except_msg = 'Unrecognized auth response'
        mock_create.side_effect = Exception(except_msg)
        token = self.examples.v3_OAUTH2_CREDENTIAL
        resp = self.call_middleware(
            headers=get_authorization_header(token),
            expected_status=401,
            method='GET', path='/vnfpkgm/v1/vnf_packages',
        )
        self.assertUnauthorizedResp(resp)
        self.assertIn(
            'Invalid token contents.',
            self.logger.output)
        self.assertIn(
            'Invalid OAuth2.0 certificate-bound access token: %s'
            % 'Token authorization failed',
            self.logger.output)

    def test_request_no_token(self):
        resp = self.call_middleware(expected_status=401)
        self.assertUnauthorizedResp(resp)

    def test_request_blank_token(self):
        resp = self.call_middleware(headers=get_authorization_header(''),
                                    expected_status=401)
        self.assertUnauthorizedResp(resp)

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
        auth_filter = oauth2_mtls_token.filter_factory(conf)
        m = auth_filter(FakeOauth2TokenV3App())
        self.assertIsInstance(m, oauth2_mtls_token.OAuth2mTlsProtocol)
