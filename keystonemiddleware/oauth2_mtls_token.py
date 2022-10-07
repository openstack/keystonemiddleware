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
import base64
import hashlib
import ssl
import webob

from oslo_log import log as logging
from oslo_serialization import jsonutils

from keystonemiddleware.auth_token import _user_plugin
from keystonemiddleware.auth_token import AuthProtocol
from keystonemiddleware import exceptions
from keystonemiddleware.i18n import _


class OAuth2mTlsProtocol(AuthProtocol):
    """Middleware that handles OAuth2.0 mutual-TLS client authentication."""

    def __init__(self, app, conf):
        log = logging.getLogger(conf.get('log_name', __name__))
        log.info('Starting Keystone oauth2_mls_token middleware')
        super(OAuth2mTlsProtocol, self).__init__(app, conf)

    def _confirm_certificate_thumbprint(self, token_thumb, peer_cert):
        """Check if the thumbprint in the token is valid.

        :rtype: if the thumbprint is valid
        """
        try:
            cert_pem = ssl.DER_cert_to_PEM_cert(peer_cert)
            thumb_sha256 = hashlib.sha256(cert_pem.encode('ascii')).digest()
            cert_thumb = base64.urlsafe_b64encode(thumb_sha256).decode('ascii')
            if cert_thumb == token_thumb:
                is_valid = True
            else:
                self.log.info('The two thumbprints do not match.')
                is_valid = False
        except Exception as error:
            self.log.exception(error)
            is_valid = False
        return is_valid

    def _is_valid_access_token(self, request):
        """Check the OAuth2.0 certificate-bound access token.

        :param request: Incoming request
        :rtype: if the access token is valid
        """
        try:
            wsgi_input = request.environ.get("wsgi.input")
            if not wsgi_input:
                self.log.warn('Unable to obtain the client certificate.')
                return False
            sock = wsgi_input.get_socket()
            if not sock:
                self.log.warn('Unable to obtain the client certificate.')
                return False
            peer_cert = sock.getpeercert(binary_form=True)
            if not peer_cert:
                self.log.warn('Unable to obtain the client certificate.')
                return False
        except Exception as error:
            self.log.warn('Unable to obtain the client certificate. %s' %
                          str(error))
            return False

        access_token = None
        if (request.authorization and
                request.authorization.authtype == 'Bearer'):
            access_token = request.authorization.params

        if not access_token:
            self.log.info('Unable to obtain the token.')
            return False

        try:
            token_data, user_auth_ref = self._do_fetch_token(
                access_token, allow_expired=False)
            self._validate_token(user_auth_ref, allow_expired=False)
            token = token_data.get('token')
            oauth2_cred = token.get('oauth2_credential')
            if not oauth2_cred:
                self.log.info(
                    'Invalid OAuth2.0 certificate-bound access token: '
                    'The token is not an OAuth2.0 credential access token.')
                return False

            token_thumb = oauth2_cred.get("x5t#S256")
            if self._confirm_certificate_thumbprint(token_thumb, peer_cert):
                self._confirm_token_bind(user_auth_ref, request)
                request.token_info = token_data
                request.token_auth = _user_plugin.UserAuthPlugin(
                    user_auth_ref, None)
                return True
            else:
                self.log.info(
                    'Invalid OAuth2.0 certificate-bound access token: '
                    'the access token dose not match the client certificate.')
                return False
        except exceptions.KeystoneMiddlewareException as err:
            self.log.info('Invalid OAuth2.0 certificate-bound access token: %s'
                          % str(err))
            return False

    def process_request(self, request):
        """Process request.

        :param request: Incoming request
        :type request: _request.AuthTokenRequest
        """
        request.remove_auth_headers()
        self._token_cache.initialize(request.environ)
        if (not self._is_valid_access_token(request)
                or "keystone.token_info" not in request.environ
                or "token" not in request.environ["keystone.token_info"]):
            self.log.info('Rejecting request')
            message = _('The request you have made requires authentication.')
            body = {'error': {
                'code': 401,
                'title': 'Unauthorized',
                'message': message,
            }}
            raise webob.exc.HTTPUnauthorized(
                body=jsonutils.dumps(body),
                headers=self._reject_auth_headers,
                charset='UTF-8',
                content_type='application/json')

        request.set_user_headers(request.token_auth.user)
        request.set_service_catalog_headers(request.token_auth.user)
        request.token_auth._auth = self._auth
        request.token_auth._session = self._session
        self.log.debug('Accepting request and inited all env fields.')


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OAuth2mTlsProtocol(app, conf)

    return auth_filter
