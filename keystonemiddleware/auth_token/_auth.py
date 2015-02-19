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

import logging

from keystoneclient import auth
from keystoneclient.auth.identity import v2
from keystoneclient.auth import token_endpoint
from keystoneclient import discover
from oslo_config import cfg

from keystonemiddleware.auth_token import _base
from keystonemiddleware.i18n import _, _LW


_LOG = logging.getLogger(__name__)


class AuthTokenPlugin(auth.BaseAuthPlugin):

    def __init__(self, auth_host, auth_port, auth_protocol, auth_admin_prefix,
                 admin_user, admin_password, admin_tenant_name, admin_token,
                 identity_uri, log):
        # NOTE(jamielennox): it does appear here that our default arguments
        # are backwards. We need to do it this way so that we can handle the
        # same deprecation strategy for CONF and the conf variable.
        if not identity_uri:
            log.warning(_LW('Configuring admin URI using auth fragments. '
                            'This is deprecated, use \'identity_uri\''
                            ' instead.'))

            if ':' in auth_host:
                # Note(dzyu) it is an IPv6 address, so it needs to be wrapped
                # with '[]' to generate a valid IPv6 URL, based on
                # http://www.ietf.org/rfc/rfc2732.txt
                auth_host = '[%s]' % auth_host

            identity_uri = '%s://%s:%s' % (auth_protocol,
                                           auth_host,
                                           auth_port)

            if auth_admin_prefix:
                identity_uri = '%s/%s' % (identity_uri,
                                          auth_admin_prefix.strip('/'))

        self._identity_uri = identity_uri.rstrip('/')

        # FIXME(jamielennox): Yes. This is wrong. We should be determining the
        # plugin to use based on a combination of discovery and inputs. Much
        # of this can be changed when we get keystoneclient 0.10. For now this
        # hardcoded path is EXACTLY the same as the original auth_token did.
        auth_url = '%s/v2.0' % self._identity_uri

        if admin_token:
            log.warning(_LW(
                "The admin_token option in the auth_token middleware is "
                "deprecated and should not be used. The admin_user and "
                "admin_password options should be used instead. The "
                "admin_token option may be removed in a future release."))
            self._plugin = token_endpoint.Token(auth_url, admin_token)
        else:
            self._plugin = v2.Password(auth_url,
                                       username=admin_user,
                                       password=admin_password,
                                       tenant_name=admin_tenant_name)

        self._LOG = log
        self._discover = None

    def get_token(self, *args, **kwargs):
        return self._plugin.get_token(*args, **kwargs)

    def get_endpoint(self, session, interface=None, version=None, **kwargs):
        """Return an endpoint for the client.

        There are no required keyword arguments to ``get_endpoint`` as a plugin
        implementation should use best effort with the information available to
        determine the endpoint.

        :param session: The session object that the auth_plugin belongs to.
        :type session: keystoneclient.session.Session
        :param tuple version: The version number required for this endpoint.
        :param str interface: what visibility the endpoint should have.

        :returns: The base URL that will be used to talk to the required
                  service or None if not available.
        :rtype: string
        """
        if interface == auth.AUTH_INTERFACE:
            return self._identity_uri

        if not version:
            # NOTE(jamielennox): This plugin can only be used within auth_token
            # and auth_token will always provide version= with requests.
            return None

        if not self._discover:
            self._discover = discover.Discover(session,
                                               auth_url=self._identity_uri,
                                               authenticated=False)

        if not self._discover.url_for(version):
            # NOTE(jamielennox): The requested version is not supported by the
            # identity server.
            return None

        # NOTE(jamielennox): for backwards compatibility here we don't
        # actually use the URL from discovery we hack it up instead. :(
        if version[0] == 2:
            return '%s/v2.0' % self._identity_uri
        elif version[0] == 3:
            return '%s/v3' % self._identity_uri

        # NOTE(jamielennox): This plugin will only get called from auth_token
        # middleware. The middleware should never request a version that the
        # plugin doesn't know how to handle.
        msg = _('Invalid version asked for in auth_token plugin')
        raise NotImplementedError(msg)

    def invalidate(self):
        return self._plugin.invalidate()

    @classmethod
    def get_options(cls):
        options = super(AuthTokenPlugin, cls).get_options()

        options.extend([
            cfg.StrOpt('auth_admin_prefix',
                       default='',
                       help='Prefix to prepend at the beginning of the path. '
                            'Deprecated, use identity_uri.'),
            cfg.StrOpt('auth_host',
                       default='127.0.0.1',
                       help='Host providing the admin Identity API endpoint. '
                            'Deprecated, use identity_uri.'),
            cfg.IntOpt('auth_port',
                       default=35357,
                       help='Port of the admin Identity API endpoint. '
                            'Deprecated, use identity_uri.'),
            cfg.StrOpt('auth_protocol',
                       default='https',
                       help='Protocol of the admin Identity API endpoint '
                            '(http or https). Deprecated, use identity_uri.'),
            cfg.StrOpt('identity_uri',
                       default=None,
                       help='Complete admin Identity API endpoint. This '
                            'should specify the unversioned root endpoint '
                            'e.g. https://localhost:35357/'),
            cfg.StrOpt('admin_token',
                       secret=True,
                       help='This option is deprecated and may be removed in '
                            'a future release. Single shared secret with the '
                            'Keystone configuration used for bootstrapping a '
                            'Keystone installation, or otherwise bypassing '
                            'the normal authentication process. This option '
                            'should not be used, use `admin_user` and '
                            '`admin_password` instead.'),
            cfg.StrOpt('admin_user',
                       help='Service username.'),
            cfg.StrOpt('admin_password',
                       secret=True,
                       help='Service user password.'),
            cfg.StrOpt('admin_tenant_name',
                       default='admin',
                       help='Service tenant name.'),
        ])

        return options


auth.register_conf_options(cfg.CONF, _base.AUTHTOKEN_GROUP)
AuthTokenPlugin.register_conf_options(cfg.CONF, _base.AUTHTOKEN_GROUP)
