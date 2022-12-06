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

import webob

from oslo_log import log as logging
from oslo_serialization import jsonutils

from keystonemiddleware.auth_token import _user_plugin
from keystonemiddleware.auth_token import AuthProtocol
from keystonemiddleware import exceptions
from keystonemiddleware.i18n import _


_LOG = logging.getLogger(__name__)


class OAuth2Protocol(AuthProtocol):
    """Middleware that handles OAuth2.0 client credentials authentication."""

    def __init__(self, app, conf):
        log = logging.getLogger(conf.get('log_name', __name__))
        log.info('Starting Keystone oauth2_token middleware')
        super(OAuth2Protocol, self).__init__(app, conf)

    def _is_valid_access_token(self, request):
        """Check if the request contains an OAuth2.0 access token.

        :param request: Incoming request
        :type request: _request.AuthTokenRequest
        """
        access_token = None
        if (request.authorization and
                request.authorization.authtype == 'Bearer'):
            access_token = request.authorization.params

        if access_token:
            try:
                token_data, user_auth_ref = self._do_fetch_token(
                    access_token, allow_expired=False)
                self._validate_token(user_auth_ref,
                                     allow_expired=False)
                token = token_data['token']
                self.validate_allowed_request(request, token)
                self._confirm_token_bind(user_auth_ref, request)
                request.token_info = token_data
                request.token_auth = _user_plugin.UserAuthPlugin(
                    user_auth_ref, None)
                return True
            except exceptions.KeystoneMiddlewareException as err:
                _LOG.info('Invalid OAuth2.0 access token: %s' % str(err))
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
            _LOG.info('Rejecting request')
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


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OAuth2Protocol(app, conf)

    return auth_filter
