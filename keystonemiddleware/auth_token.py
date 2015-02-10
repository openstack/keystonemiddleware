# Copyright 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Token-based Authentication Middleware

This WSGI component:

* Verifies that incoming client requests have valid tokens by validating
  tokens with the auth service.
* Rejects unauthenticated requests unless the auth_token middleware is in
  'delay_auth_decision' mode, which means the final decision is delegated to
  the downstream WSGI component (usually the OpenStack service).
* Collects and forwards identity information based on a valid token
  such as user name, tenant, etc

Refer to: http://docs.openstack.org/developer/keystonemiddleware/\
middlewarearchitecture.html

Run this module directly to start a protected echo service on port 8000::

 $ python -m keystonemiddleware.auth_token

When the ``auth_token`` module authenticates a request, the echo service
will respond with all the environment variables presented to it by this
module.


Headers
-------

The auth_token middleware uses headers sent in by the client on the request
and sets headers and environment variables for the downstream WSGI component.

Coming in from initial call from client or customer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    The client token being passed in.

HTTP_X_SERVICE_TOKEN
    A service token being passed in.

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

WWW-Authenticate
    HTTP header returned to a user indicating which endpoint to use
    to retrieve a new token

What auth_token adds to the request for use by the OpenStack service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using composite authentication (a user and service token are
present) additional service headers relating to the service user
will be added. They take the same form as the standard headers but add
'_SERVICE_'. These headers will not exist in the environment if no
service token is present.

HTTP_X_IDENTITY_STATUS
    'Confirmed' or 'Invalid'
    The underlying service will only see a value of 'Invalid' if the Middleware
    is configured to run in 'delay_auth_decision' mode

HTTP_X_DOMAIN_ID, HTTP_X_SERVICE_DOMAIN_ID
    Identity service managed unique identifier, string. Only present if
    this is a domain-scoped v3 token.

HTTP_X_DOMAIN_NAME, HTTP_X_SERVICE_DOMAIN_NAME
    Unique domain name, string. Only present if this is a domain-scoped
    v3 token.

HTTP_X_PROJECT_ID, HTTP_X_SERVICE_PROJECT_ID
    Identity service managed unique identifier, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_NAME, HTTP_X_SERVICE_PROJECT_NAME
    Project name, unique within owning domain, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_DOMAIN_ID, HTTP_X_SERVICE_PROJECT_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    project, string.  Only present if this is a project-scoped v3 token. If
    this variable is set, this indicates that the PROJECT_NAME can only
    be assumed to be unique within this domain.

HTTP_X_PROJECT_DOMAIN_NAME, HTTP_X_SERVICE_PROJECT_DOMAIN_NAME
    Name of owning domain of project, string. Only present if this is a
    project-scoped v3 token. If this variable is set, this indicates that
    the PROJECT_NAME can only be assumed to be unique within this domain.

HTTP_X_USER_ID, HTTP_X_SERVICE_USER_ID
    Identity-service managed unique identifier, string

HTTP_X_USER_NAME, HTTP_X_SERVICE_USER_NAME
    User identifier, unique within owning domain, string

HTTP_X_USER_DOMAIN_ID, HTTP_X_SERVICE_USER_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    user, string. If this variable is set, this indicates that the USER_NAME
    can only be assumed to be unique within this domain.

HTTP_X_USER_DOMAIN_NAME, HTTP_X_SERVICE_USER_DOMAIN_NAME
    Name of owning domain of user, string. If this variable is set, this
    indicates that the USER_NAME can only be assumed to be unique within
    this domain.

HTTP_X_ROLES, HTTP_X_SERVICE_ROLES
    Comma delimited list of case-sensitive role names

HTTP_X_SERVICE_CATALOG
    json encoded service catalog (optional).
    For compatibility reasons this catalog will always be in the V2 catalog
    format even if it is a v3 token.

    Note: This is an exception in that it contains 'SERVICE' but relates to a
          user token, not a service token. The existing user's
          catalog can be very large; it was decided not to present a catalog
          relating to the service token to avoid using more HTTP header space.

HTTP_X_TENANT_ID
    *Deprecated* in favor of HTTP_X_PROJECT_ID
    Identity service managed unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID

HTTP_X_TENANT_NAME
    *Deprecated* in favor of HTTP_X_PROJECT_NAME
    Project identifier, unique within owning domain, string. For v3 tokens,
    this will be set to the same value as HTTP_X_PROJECT_NAME

HTTP_X_TENANT
    *Deprecated* in favor of HTTP_X_TENANT_ID and HTTP_X_TENANT_NAME
    identity server-assigned unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME
    User name, unique within owning domain, string

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES
    Will contain the same values as HTTP_X_ROLES.

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

These variables are set in the request environment for use by the downstream
WSGI component.

keystone.token_info
    Information about the token discovered in the process of validation.  This
    may include extended information returned by the token validation call, as
    well as basic information about the tenant and user.

keystone.token_auth
    A keystoneclient auth plugin that may be used with a
    :py:class:`keystoneclient.session.Session`. This plugin will load the
    authentication data provided to auth_token middleware.

"""

import contextlib
import datetime
import logging
import os
import stat
import tempfile

from keystoneclient import access
from keystoneclient import adapter
from keystoneclient import auth
from keystoneclient.auth.identity import base as base_identity
from keystoneclient.auth.identity import v2
from keystoneclient.auth import token_endpoint
from keystoneclient.common import cms
from keystoneclient import discover
from keystoneclient import exceptions
from keystoneclient import session
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six
from six.moves import urllib

from keystonemiddleware import _memcache_crypt as memcache_crypt
from keystonemiddleware.i18n import _, _LC, _LE, _LI, _LW
from keystonemiddleware.openstack.common import memorycache


# alternative middleware configuration in the main application's
# configuration file e.g. in nova.conf
# [keystone_authtoken]
# auth_host = 127.0.0.1
# auth_port = 35357
# auth_protocol = http
# admin_tenant_name = admin
# admin_user = admin
# admin_password = badpassword

# when deploy Keystone auth_token middleware with Swift, user may elect
# to use Swift memcache instead of the local auth_token memcache. Swift
# memcache is passed in from the request environment and its identified by the
# 'swift.cache' key. However it could be different, depending on deployment.
# To use Swift memcache, you must set the 'cache' option to the environment
# key where the Swift cache object is stored.


# NOTE(jamielennox): A number of options below are deprecated however are left
# in the list and only mentioned as deprecated in the help string. This is
# because we have to provide the same deprecation functionality for arguments
# passed in via the conf in __init__ (from paste) and there is no way to test
# that the default value was set or not in CONF.
# Also if we were to remove the options from the CONF list (as typical CONF
# deprecation works) then other projects will not be able to override the
# options via CONF.

_OPTS = [
    cfg.StrOpt('auth_uri',
               default=None,
               # FIXME(dolph): should be default='http://127.0.0.1:5000/v2.0/',
               # or (depending on client support) an unversioned, publicly
               # accessible identity endpoint (see bug 1207517)
               help='Complete public Identity API endpoint.'),
    cfg.StrOpt('auth_version',
               default=None,
               help='API version of the admin Identity API endpoint.'),
    cfg.BoolOpt('delay_auth_decision',
                default=False,
                help='Do not handle authorization requests within the'
                ' middleware, but delegate the authorization decision to'
                ' downstream WSGI components.'),
    cfg.IntOpt('http_connect_timeout',
               default=None,
               help='Request timeout value for communicating with Identity'
               ' API server.'),
    cfg.IntOpt('http_request_max_retries',
               default=3,
               help='How many times are we trying to reconnect when'
               ' communicating with Identity API Server.'),
    cfg.StrOpt('cache',
               default=None,
               help='Env key for the swift cache.'),
    cfg.StrOpt('certfile',
               help='Required if identity server requires client certificate'),
    cfg.StrOpt('keyfile',
               help='Required if identity server requires client certificate'),
    cfg.StrOpt('cafile', default=None,
               help='A PEM encoded Certificate Authority to use when '
                    'verifying HTTPs connections. Defaults to system CAs.'),
    cfg.BoolOpt('insecure', default=False, help='Verify HTTPS connections.'),
    cfg.StrOpt('signing_dir',
               help='Directory used to cache files related to PKI tokens.'),
    cfg.ListOpt('memcached_servers',
                deprecated_name='memcache_servers',
                help='Optionally specify a list of memcached server(s) to'
                ' use for caching. If left undefined, tokens will instead be'
                ' cached in-process.'),
    cfg.IntOpt('token_cache_time',
               default=300,
               help='In order to prevent excessive effort spent validating'
               ' tokens, the middleware caches previously-seen tokens for a'
               ' configurable duration (in seconds). Set to -1 to disable'
               ' caching completely.'),
    cfg.IntOpt('revocation_cache_time',
               default=10,
               help='Determines the frequency at which the list of revoked'
               ' tokens is retrieved from the Identity service (in seconds). A'
               ' high number of revocation events combined with a low cache'
               ' duration may significantly reduce performance.'),
    cfg.StrOpt('memcache_security_strategy',
               default=None,
               help='(Optional) If defined, indicate whether token data'
               ' should be authenticated or authenticated and encrypted.'
               ' Acceptable values are MAC or ENCRYPT.  If MAC, token data is'
               ' authenticated (with HMAC) in the cache. If ENCRYPT, token'
               ' data is encrypted and authenticated in the cache. If the'
               ' value is not one of these options or empty, auth_token will'
               ' raise an exception on initialization.'),
    cfg.StrOpt('memcache_secret_key',
               default=None,
               secret=True,
               help='(Optional, mandatory if memcache_security_strategy is'
               ' defined) This string is used for key derivation.'),
    cfg.IntOpt('memcache_pool_dead_retry',
               default=5 * 60,
               help='(Optional) Number of seconds memcached server is'
               ' considered dead before it is tried again.'),
    cfg.IntOpt('memcache_pool_maxsize',
               default=10,
               help='(Optional) Maximum total number of open connections to'
               ' every memcached server.'),
    cfg.IntOpt('memcache_pool_socket_timeout',
               default=3,
               help='(Optional) Socket timeout in seconds for communicating '
                    'with a memcache server.'),
    cfg.IntOpt('memcache_pool_unused_timeout',
               default=60,
               help='(Optional) Number of seconds a connection to memcached'
               ' is held unused in the pool before it is closed.'),
    cfg.IntOpt('memcache_pool_conn_get_timeout',
               default=10,
               help='(Optional) Number of seconds that an operation will wait '
                    'to get a memcache client connection from the pool.'),
    cfg.BoolOpt('memcache_use_advanced_pool',
                default=False,
                help='(Optional) Use the advanced (eventlet safe) memcache '
                     'client pool. The advanced pool will only work under '
                     'python 2.x.'),
    cfg.BoolOpt('include_service_catalog',
                default=True,
                help='(Optional) Indicate whether to set the X-Service-Catalog'
                ' header. If False, middleware will not ask for service'
                ' catalog on token validation and will not set the'
                ' X-Service-Catalog header.'),
    cfg.StrOpt('enforce_token_bind',
               default='permissive',
               help='Used to control the use and type of token binding. Can'
               ' be set to: "disabled" to not check token binding.'
               ' "permissive" (default) to validate binding information if the'
               ' bind type is of a form known to the server and ignore it if'
               ' not. "strict" like "permissive" but if the bind type is'
               ' unknown the token will be rejected. "required" any form of'
               ' token binding is needed to be allowed. Finally the name of a'
               ' binding method that must be present in tokens.'),
    cfg.BoolOpt('check_revocations_for_cached', default=False,
                help='If true, the revocation list will be checked for cached'
                ' tokens. This requires that PKI tokens are configured on the'
                ' identity server.'),
    cfg.ListOpt('hash_algorithms', default=['md5'],
                help='Hash algorithms to use for hashing PKI tokens. This may'
                ' be a single algorithm or multiple. The algorithms are those'
                ' supported by Python standard hashlib.new(). The hashes will'
                ' be tried in the order given, so put the preferred one first'
                ' for performance. The result of the first hash will be stored'
                ' in the cache. This will typically be set to multiple values'
                ' only while migrating from a less secure algorithm to a more'
                ' secure one. Once all the old tokens are expired this option'
                ' should be set to a single value for better performance.'),
]

_AUTHTOKEN_GROUP = 'keystone_authtoken'
CONF = cfg.CONF
CONF.register_opts(_OPTS, group=_AUTHTOKEN_GROUP)
auth.register_conf_options(CONF, _AUTHTOKEN_GROUP)

_HEADER_TEMPLATE = {
    'X%s-Domain-Id': 'domain_id',
    'X%s-Domain-Name': 'domain_name',
    'X%s-Project-Id': 'project_id',
    'X%s-Project-Name': 'project_name',
    'X%s-Project-Domain-Id': 'project_domain_id',
    'X%s-Project-Domain-Name': 'project_domain_name',
    'X%s-User-Id': 'user_id',
    'X%s-User-Name': 'username',
    'X%s-User-Domain-Id': 'user_domain_id',
    'X%s-User-Domain-Name': 'user_domain_name',
}

_DEPRECATED_HEADER_TEMPLATE = {
    'X-User': 'username',
    'X-Tenant-Id': 'project_id',
    'X-Tenant-Name': 'project_name',
    'X-Tenant': 'project_name',
}


class _BIND_MODE(object):
    DISABLED = 'disabled'
    PERMISSIVE = 'permissive'
    STRICT = 'strict'
    REQUIRED = 'required'
    KERBEROS = 'kerberos'


def _token_is_v2(token_info):
    return ('access' in token_info)


def _token_is_v3(token_info):
    return ('token' in token_info)


def _get_token_expiration(data):
    if not data:
        raise InvalidToken(_('Token authorization failed'))
    if _token_is_v2(data):
        return data['access']['token']['expires']
    elif _token_is_v3(data):
        return data['token']['expires_at']
    else:
        raise InvalidToken(_('Token authorization failed'))


def _confirm_token_not_expired(expires):
    expires = timeutils.parse_isotime(expires)
    expires = timeutils.normalize_time(expires)
    utcnow = timeutils.utcnow()
    if utcnow >= expires:
        raise InvalidToken(_('Token authorization failed'))


def _v3_to_v2_catalog(catalog):
    """Convert a catalog to v2 format.

    X_SERVICE_CATALOG must be specified in v2 format. If you get a token
    that is in v3 convert it.
    """
    v2_services = []
    for v3_service in catalog:
        # first copy over the entries we allow for the service
        v2_service = {'type': v3_service['type']}
        try:
            v2_service['name'] = v3_service['name']
        except KeyError:
            pass

        # now convert the endpoints. Because in v3 we specify region per
        # URL not per group we have to collect all the entries of the same
        # region together before adding it to the new service.
        regions = {}
        for v3_endpoint in v3_service.get('endpoints', []):
            region_name = v3_endpoint.get('region')
            try:
                region = regions[region_name]
            except KeyError:
                region = {'region': region_name} if region_name else {}
                regions[region_name] = region

            interface_name = v3_endpoint['interface'].lower() + 'URL'
            region[interface_name] = v3_endpoint['url']

        v2_service['endpoints'] = list(regions.values())
        v2_services.append(v2_service)

    return v2_services


def _safe_quote(s):
    """URL-encode strings that are not already URL-encoded."""
    return urllib.parse.quote(s) if s == urllib.parse.unquote(s) else s


def _conf_values_type_convert(conf):
    """Convert conf values into correct type."""
    if not conf:
        return {}

    opt_types = {}
    for o in (_OPTS + _AuthTokenPlugin.get_options()):
        type_dest = (getattr(o, 'type', str), o.dest)
        opt_types[o.dest] = type_dest
        # Also add the deprecated name with the same type and dest.
        for d_o in o.deprecated_opts:
            opt_types[d_o.name] = type_dest

    opts = {}
    for k, v in six.iteritems(conf):
        dest = k
        try:
            if v is not None:
                type_, dest = opt_types[k]
                v = type_(v)
        except KeyError:
            # This option is not known to auth_token.
            pass
        except ValueError as e:
            raise ConfigurationError(
                _('Unable to convert the value of %(key)s option into correct '
                  'type: %(ex)s') % {'key': k, 'ex': e})
        opts[dest] = v
    return opts


class InvalidToken(Exception):
    pass


class ServiceError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class RevocationListError(Exception):
    pass


class _MiniResp(object):
    def __init__(self, error_message, env, headers=[]):
        # The HEAD method is unique: it must never return a body, even if
        # it reports an error (RFC-2616 clause 9.4). We relieve callers
        # from varying the error responses depending on the method.
        if env['REQUEST_METHOD'] == 'HEAD':
            self.body = ['']
        else:
            self.body = [error_message.encode()]
        self.headers = list(headers)
        self.headers.append(('Content-type', 'text/plain'))


class _AuthTokenPlugin(auth.BaseAuthPlugin):

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
        options = super(_AuthTokenPlugin, cls).get_options()

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


_AuthTokenPlugin.register_conf_options(CONF, _AUTHTOKEN_GROUP)


class _TokenData(object):
    """An abstraction to show auth_token consumers some of the token contents.

    This is a simplified and cleaned up keystoneclient.access.AccessInfo object
    with which services relying on auth_token middleware can find details of
    the current token.
    """

    def __init__(self, auth_ref):
        self._stored_auth_ref = auth_ref

    @property
    def _is_v2(self):
        return self._stored_auth_ref.version == 'v2.0'

    @property
    def auth_token(self):
        """The token data used to authenticate requests.

        :returns: token data.
        :rtype: str
        """
        return self._stored_auth_ref.auth_token

    @property
    def user_id(self):
        """The user id associated with the authentication request.

        :rtype: str
        """
        return self._stored_auth_ref.user_id

    @property
    def user_domain_id(self):
        """Returns the domain id of the user associated with the authentication
        request.

        :returns: str
        """
        # NOTE(jamielennox): v2 AccessInfo returns 'default' for domain_id
        # because it can't know that value. We want to return None instead.
        if self._is_v2:
            return None

        return self._stored_auth_ref.user_domain_id

    @property
    def project_id(self):
        """The project ID associated with the authentication.

        :rtype: str
        """
        return self._stored_auth_ref.project_id

    @property
    def project_domain_id(self):
        """The domain id of the project associated with the authentication
        request.

        :rtype: str
        """
        # NOTE(jamielennox): v2 AccessInfo returns 'default' for domain_id
        # because it can't know that value. We want to return None instead.
        if self._is_v2:
            return None

        return self._stored_auth_ref.project_domain_id

    @property
    def trust_id(self):
        """Returns the trust id associated with the authentication request..

        :rtype: str
        """
        return self._stored_auth_ref.trust_id

    @property
    def role_ids(self):
        """Role ids of the user associated with the authentication request.

        :rtype: set(str)
        """
        return frozenset(self._stored_auth_ref.role_ids or [])

    @property
    def role_names(self):
        """Role names of the user associated with the authentication request.

        :rtype: set(str)
        """
        return frozenset(self._stored_auth_ref.role_names or [])


class _UserAuthPlugin(base_identity.BaseIdentityPlugin):
    """The incoming authentication credentials.

    A plugin that represents the incoming user credentials. This can be
    consumed by applications.

    This object is not expected to be constructed directly by users. It is
    created and passed by auth_token middleware and then can be used as the
    authentication plugin when communicating via a session.
    """

    def __init__(self, user_auth_ref, serv_auth_ref):
        super(_UserAuthPlugin, self).__init__(reauthenticate=False)
        self._user_auth_ref = user_auth_ref
        self._serv_auth_ref = serv_auth_ref
        self._user_data = None
        self._serv_data = None

    @property
    def has_user_token(self):
        """Did this authentication request contained a user auth token."""
        return self._user_auth_ref is not None

    @property
    def user(self):
        """Authentication information about the user token.

        Will return None if a user token was not passed with this request.
        """
        if not self.has_user_token:
            return None

        if not self._user_data:
            self._user_data = _TokenData(self._user_auth_ref)

        return self._user_data

    @property
    def has_service_token(self):
        """Did this authentication request contained a service token."""
        return self._serv_auth_ref is not None

    @property
    def service(self):
        """Authentication information about the service token.

        Will return None if a user token was not passed with this request.
        """
        if not self.has_service_token:
            return None

        if not self._serv_data:
            self._serv_data = _TokenData(self._serv_auth_ref)

        return self._serv_data

    def get_auth_ref(self, session, **kwargs):
        # NOTE(jamielennox): We will always use the auth_ref that was
        # calculated by the middleware. reauthenticate=False in __init__ should
        # ensure that this function is only called on the first access.
        return self._user_auth_ref


class AuthProtocol(object):
    """Middleware that handles authenticating client calls."""

    def __init__(self, app, conf):
        self._LOG = logging.getLogger(conf.get('log_name', __name__))
        self._LOG.info(_LI('Starting Keystone auth_token middleware'))
        # NOTE(wanghong): If options are set in paste file, all the option
        # values passed into conf are string type. So, we should convert the
        # conf value into correct type.
        self._conf = _conf_values_type_convert(conf)
        self._app = app

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self._delay_auth_decision = self._conf_get('delay_auth_decision')
        self._include_service_catalog = self._conf_get(
            'include_service_catalog')

        self._identity_server = self._create_identity_server()

        self._auth_uri = self._conf_get('auth_uri')
        if not self._auth_uri:
            self._LOG.warning(
                _LW('Configuring auth_uri to point to the public identity '
                    'endpoint is required; clients may not be able to '
                    'authenticate against an admin endpoint'))

            # FIXME(dolph): drop support for this fallback behavior as
            # documented in bug 1207517.

            self._auth_uri = self._identity_server.auth_uri

        # signing
        self._signing_dirname = self._conf_get('signing_dir')
        if self._signing_dirname is None:
            self._signing_dirname = tempfile.mkdtemp(
                prefix='keystone-signing-')
        self._LOG.info(
            _LI('Using %s as cache directory for signing certificate'),
            self._signing_dirname)
        self._verify_signing_dir()

        val = '%s/signing_cert.pem' % self._signing_dirname
        self._signing_cert_file_name = val
        val = '%s/cacert.pem' % self._signing_dirname
        self._signing_ca_file_name = val
        val = '%s/revoked.pem' % self._signing_dirname
        self._revoked_file_name = val

        self._token_cache = self._token_cache_factory()
        self._token_revocation_list_prop = None
        self._token_revocation_list_fetched_time_prop = None
        self._token_revocation_list_cache_timeout = datetime.timedelta(
            seconds=self._conf_get('revocation_cache_time'))

        self._check_revocations_for_cached = self._conf_get(
            'check_revocations_for_cached')
        self._init_auth_headers()

    def _conf_get(self, name):
        # try config from paste-deploy first
        if name in self._conf:
            return self._conf[name]
        else:
            return CONF.keystone_authtoken[name]

    def _call_app(self, env, start_response):
        # NOTE(jamielennox): We wrap the given start response so that if an
        # application with a 'delay_auth_decision' setting fails, or otherwise
        # raises Unauthorized that we include the Authentication URL headers.
        def _fake_start_response(status, response_headers, exc_info=None):
            if status.startswith('401'):
                response_headers.extend(self._reject_auth_headers)

            return start_response(status, response_headers, exc_info)

        return self._app(env, _fake_start_response)

    def __call__(self, env, start_response):
        """Handle incoming request.

        Authenticate send downstream on success. Reject request if
        we can't authenticate.

        """
        def _fmt_msg(env):
            msg = ('user: user_id %s, project_id %s, roles %s '
                   'service: user_id %s, project_id %s, roles %s' % (
                       env.get('HTTP_X_USER_ID'), env.get('HTTP_X_PROJECT_ID'),
                       env.get('HTTP_X_ROLES'),
                       env.get('HTTP_X_SERVICE_USER_ID'),
                       env.get('HTTP_X_SERVICE_PROJECT_ID'),
                       env.get('HTTP_X_SERVICE_ROLES')))
            return msg

        self._token_cache.initialize(env)
        self._remove_auth_headers(env)

        try:
            user_auth_ref = None
            serv_auth_ref = None

            try:
                self._LOG.debug('Authenticating user token')
                user_token = self._get_user_token_from_header(env)
                user_token_info = self._validate_token(user_token, env)
                user_auth_ref = access.AccessInfo.factory(
                    body=user_token_info,
                    auth_token=user_token)
                env['keystone.token_info'] = user_token_info
                user_headers = self._build_user_headers(user_auth_ref,
                                                        user_token_info)
                self._add_headers(env, user_headers)
            except InvalidToken:
                if self._delay_auth_decision:
                    self._LOG.info(
                        _LI('Invalid user token - deferring reject '
                            'downstream'))
                    self._add_headers(env, {'X-Identity-Status': 'Invalid'})
                else:
                    self._LOG.info(
                        _LI('Invalid user token - rejecting request'))
                    return self._reject_request(env, start_response)

            try:
                self._LOG.debug('Authenticating service token')
                serv_token = self._get_service_token_from_header(env)
                if serv_token is not None:
                    serv_token_info = self._validate_token(
                        serv_token, env)
                    serv_auth_ref = access.AccessInfo.factory(
                        body=serv_token_info,
                        auth_token=serv_token)
                    serv_headers = self._build_service_headers(serv_token_info)
                    self._add_headers(env, serv_headers)
            except InvalidToken:
                # Delayed auth not currently supported for service tokens.
                # (Can be implemented if a use case is found.)
                self._LOG.info(
                    _LI('Invalid service token - rejecting request'))
                return self._reject_request(env, start_response)

            env['keystone.token_auth'] = _UserAuthPlugin(user_auth_ref,
                                                         serv_auth_ref)

        except ServiceError as e:
            self._LOG.critical(_LC('Unable to obtain admin token: %s'), e)
            return self._do_503_error(env, start_response)

        self._LOG.debug("Received request from %s", _fmt_msg(env))

        return self._call_app(env, start_response)

    def _do_503_error(self, env, start_response):
        resp = _MiniResp('Service unavailable', env)
        start_response('503 Service Unavailable', resp.headers)
        return resp.body

    def _init_auth_headers(self):
        """Initialize auth header list.

        Both user and service token headers are generated.
        """
        auth_headers = ['X-Service-Catalog',
                        'X-Identity-Status',
                        'X-Roles',
                        'X-Service-Roles']
        for key in six.iterkeys(_HEADER_TEMPLATE):
            auth_headers.append(key % '')
            # Service headers
            auth_headers.append(key % '-Service')

        # Deprecated headers
        auth_headers.append('X-Role')
        for key in six.iterkeys(_DEPRECATED_HEADER_TEMPLATE):
            auth_headers.append(key)

        self._auth_headers = auth_headers

    def _remove_auth_headers(self, env):
        """Remove headers so a user can't fake authentication.

        Both user and service token headers are removed.

        :param env: wsgi request environment

        """
        self._LOG.debug('Removing headers from request environment: %s',
                        ','.join(self._auth_headers))
        self._remove_headers(env, self._auth_headers)

    def _get_user_token_from_header(self, env):
        """Get token id from request.

        :param env: wsgi request environment
        :returns: token id
        :raises InvalidToken: if no token is provided in request

        """
        token = self._get_header(env, 'X-Auth-Token',
                                 self._get_header(env, 'X-Storage-Token'))
        if token:
            return token
        else:
            if not self._delay_auth_decision:
                self._LOG.warn(_LW('Unable to find authentication token'
                                   ' in headers'))
                self._LOG.debug('Headers: %s', env)
            raise InvalidToken(_('Unable to find token in headers'))

    def _get_service_token_from_header(self, env):
        """Get service token id from request.

        :param env: wsgi request environment
        :returns: service token id or None if not present

        """
        return self._get_header(env, 'X-Service-Token')

    @property
    def _reject_auth_headers(self):
        header_val = 'Keystone uri=\'%s\'' % self._auth_uri
        return [('WWW-Authenticate', header_val)]

    def _reject_request(self, env, start_response):
        """Redirect client to auth server.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns: HTTPUnauthorized http response

        """
        resp = _MiniResp('Authentication required',
                         env, self._reject_auth_headers)
        start_response('401 Unauthorized', resp.headers)
        return resp.body

    def _validate_token(self, token, env, retry=True):
        """Authenticate user token

        :param token: token id
        :param env: wsgi environment
        :param retry: Ignored, as it is not longer relevant
        :returns: uncrypted body of the token if the token is valid
        :raises InvalidToken: if token is rejected

        """
        token_id = None

        try:
            token_ids, cached = self._token_cache.get(token)
            token_id = token_ids[0]
            if cached:
                # Token was retrieved from the cache. In this case, there's no
                # need to check that the token is expired because the cache
                # fetch fails for an expired token. Also, there's no need to
                # put the token in the cache because it's already in the cache.

                data = cached

                if self._check_revocations_for_cached:
                    # A token stored in Memcached might have been revoked
                    # regardless of initial mechanism used to validate it,
                    # and needs to be checked.
                    for tid in token_ids:
                        is_revoked = self._is_token_id_in_revoked_list(tid)
                        if is_revoked:
                            self._LOG.debug(
                                'Token is marked as having been revoked')
                            raise InvalidToken(
                                _('Token authorization failed'))
                self._confirm_token_bind(data, env)
            else:
                verified = None
                # Token wasn't cached. In this case, the token needs to be
                # checked that it's not expired, and also put in the cache.
                try:
                    if cms.is_pkiz(token):
                        verified = self._verify_pkiz_token(token, token_ids)
                    elif cms.is_asn1_token(token):
                        verified = self._verify_signed_token(token, token_ids)
                except exceptions.CertificateConfigError:
                    self._LOG.warn(_LW('Fetch certificate config failed, '
                                       'fallback to online validation.'))
                except RevocationListError:
                    self._LOG.warn(_LW('Fetch revocation list failed, '
                                       'fallback to online validation.'))

                if verified is not None:
                    data = jsonutils.loads(verified)
                    expires = _get_token_expiration(data)
                    _confirm_token_not_expired(expires)
                else:
                    data = self._identity_server.verify_token(token, retry)
                    # No need to confirm token expiration here since
                    # verify_token fails for expired tokens.
                    expires = _get_token_expiration(data)
                self._confirm_token_bind(data, env)
                self._token_cache.store(token_id, data, expires)
            return data
        except (exceptions.ConnectionRefused, exceptions.RequestTimeout):
            self._LOG.debug('Token validation failure.', exc_info=True)
            self._LOG.warn(_LW('Authorization failed for token'))
            raise InvalidToken(_('Token authorization failed'))
        except ServiceError:
            raise
        except Exception:
            self._LOG.debug('Token validation failure.', exc_info=True)
            if token_id:
                self._token_cache.store_invalid(token_id)
            self._LOG.warn(_LW('Authorization failed for token'))
            raise InvalidToken(_('Token authorization failed'))

    def _build_user_headers(self, auth_ref, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by identity
                           server on authentication
        :raises InvalidToken: when unable to parse token object

        """
        roles = ','.join(auth_ref.role_names)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise InvalidToken(_('Unable to determine tenancy.'))

        rval = {
            'X-Identity-Status': 'Confirmed',
            'X-Roles': roles,
        }

        for header_tmplt, attr in six.iteritems(_HEADER_TEMPLATE):
            rval[header_tmplt % ''] = getattr(auth_ref, attr)

        # Deprecated headers
        rval['X-Role'] = roles
        for header_tmplt, attr in six.iteritems(_DEPRECATED_HEADER_TEMPLATE):
            rval[header_tmplt] = getattr(auth_ref, attr)

        if self._include_service_catalog and auth_ref.has_service_catalog():
            catalog = auth_ref.service_catalog.get_data()
            if _token_is_v3(token_info):
                catalog = _v3_to_v2_catalog(catalog)
            rval['X-Service-Catalog'] = jsonutils.dumps(catalog)

        return rval

    def _build_service_headers(self, token_info):
        """Convert token object into service headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by identity
                           server on authentication
        :raises InvalidToken: when unable to parse token object

        """
        auth_ref = access.AccessInfo.factory(body=token_info)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise InvalidToken(_('Unable to determine service tenancy.'))

        roles = ','.join(auth_ref.role_names)
        rval = {
            'X-Service-Roles': roles,
        }

        header_type = '-Service'
        for header_tmplt, attr in six.iteritems(_HEADER_TEMPLATE):
            rval[header_tmplt % header_type] = getattr(auth_ref, attr)

        return rval

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :returns: wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return 'HTTP_%s' % key.replace('-', '_').upper()

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        for (k, v) in six.iteritems(headers):
            env_key = self._header_to_env_var(k)
            env[env_key] = v

    def _remove_headers(self, env, keys):
        """Remove http headers from environment."""
        for k in keys:
            env_key = self._header_to_env_var(k)
            try:
                del env[env_key]
            except KeyError:
                pass

    def _get_header(self, env, key, default=None):
        """Get http header from environment."""
        env_key = self._header_to_env_var(key)
        return env.get(env_key, default)

    def _invalid_user_token(self, msg=False):
        # NOTE(jamielennox): use False as the default so that None is valid
        if msg is False:
            msg = _('Token authorization failed')

        raise InvalidToken(msg)

    def _confirm_token_bind(self, data, env):
        bind_mode = self._conf_get('enforce_token_bind')

        if bind_mode == _BIND_MODE.DISABLED:
            return

        try:
            if _token_is_v2(data):
                bind = data['access']['token']['bind']
            elif _token_is_v3(data):
                bind = data['token']['bind']
            else:
                self._invalid_user_token()
        except KeyError:
            bind = {}

        # permissive and strict modes don't require there to be a bind
        permissive = bind_mode in (_BIND_MODE.PERMISSIVE, _BIND_MODE.STRICT)

        if not bind:
            if permissive:
                # no bind provided and none required
                return
            else:
                self._LOG.info(_LI('No bind information present in token.'))
                self._invalid_user_token()

        # get the named mode if bind_mode is not one of the predefined
        if permissive or bind_mode == _BIND_MODE.REQUIRED:
            name = None
        else:
            name = bind_mode

        if name and name not in bind:
            self._LOG.info(_LI('Named bind mode %s not in bind information'),
                           name)
            self._invalid_user_token()

        for bind_type, identifier in six.iteritems(bind):
            if bind_type == _BIND_MODE.KERBEROS:
                if not env.get('AUTH_TYPE', '').lower() == 'negotiate':
                    self._LOG.info(_LI('Kerberos credentials required and '
                                       'not present.'))
                    self._invalid_user_token()

                if not env.get('REMOTE_USER') == identifier:
                    self._LOG.info(_LI('Kerberos credentials do not match '
                                       'those in bind.'))
                    self._invalid_user_token()

                self._LOG.debug('Kerberos bind authentication successful.')

            elif bind_mode == _BIND_MODE.PERMISSIVE:
                self._LOG.debug('Ignoring Unknown bind for permissive mode: '
                                '%(bind_type)s: %(identifier)s.',
                                {'bind_type': bind_type,
                                 'identifier': identifier})

            else:
                self._LOG.info(
                    _LI('Couldn`t verify unknown bind: %(bind_type)s: '
                        '%(identifier)s.'),
                    {'bind_type': bind_type, 'identifier': identifier})
                self._invalid_user_token()

    def _is_signed_token_revoked(self, token_ids):
        """Indicate whether the token appears in the revocation list."""
        for token_id in token_ids:
            if self._is_token_id_in_revoked_list(token_id):
                self._LOG.debug('Token is marked as having been revoked')
                return True
        return False

    def _is_token_id_in_revoked_list(self, token_id):
        """Indicate whether the token_id appears in the revocation list."""
        revocation_list = self._token_revocation_list
        revoked_tokens = revocation_list.get('revoked', None)
        if not revoked_tokens:
            return False

        revoked_ids = (x['id'] for x in revoked_tokens)
        return token_id in revoked_ids

    def _cms_verify(self, data, inform=cms.PKI_ASN1_FORM):
        """Verifies the signature of the provided data's IAW CMS syntax.

        If either of the certificate files might be missing, fetch them and
        retry.
        """
        def verify():
            try:
                return cms.cms_verify(data, self._signing_cert_file_name,
                                      self._signing_ca_file_name,
                                      inform=inform).decode('utf-8')
            except cms.subprocess.CalledProcessError as err:
                self._LOG.warning(_LW('Verify error: %s'), err)
                raise

        try:
            return verify()
        except exceptions.CertificateConfigError:
            # the certs might be missing; unconditionally fetch to avoid racing
            self._fetch_signing_cert()
            self._fetch_ca_cert()

            try:
                # retry with certs in place
                return verify()
            except exceptions.CertificateConfigError as err:
                # if this is still occurring, something else is wrong and we
                # need err.output to identify the problem
                self._LOG.error(_LE('CMS Verify output: %s'), err.output)
                raise

    def _verify_signed_token(self, signed_text, token_ids):
        """Check that the token is unrevoked and has a valid signature."""
        if self._is_signed_token_revoked(token_ids):
            raise InvalidToken(_('Token has been revoked'))

        formatted = cms.token_to_cms(signed_text)
        verified = self._cms_verify(formatted)
        return verified

    def _verify_pkiz_token(self, signed_text, token_ids):
        if self._is_signed_token_revoked(token_ids):
            raise InvalidToken(_('Token has been revoked'))
        try:
            uncompressed = cms.pkiz_uncompress(signed_text)
            verified = self._cms_verify(uncompressed, inform=cms.PKIZ_CMS_FORM)
            return verified
        # TypeError If the signed_text is not zlib compressed
        except TypeError:
            raise InvalidToken(signed_text)

    def _verify_signing_dir(self):
        if os.path.exists(self._signing_dirname):
            if not os.access(self._signing_dirname, os.W_OK):
                raise ConfigurationError(
                    _('unable to access signing_dir %s') %
                    self._signing_dirname)
            uid = os.getuid()
            if os.stat(self._signing_dirname).st_uid != uid:
                self._LOG.warning(_LW('signing_dir is not owned by %s'), uid)
            current_mode = stat.S_IMODE(os.stat(self._signing_dirname).st_mode)
            if current_mode != stat.S_IRWXU:
                self._LOG.warning(
                    _LW('signing_dir mode is %(mode)s instead of %(need)s'),
                    {'mode': oct(current_mode), 'need': oct(stat.S_IRWXU)})
        else:
            os.makedirs(self._signing_dirname, stat.S_IRWXU)

    @property
    def _token_revocation_list_fetched_time(self):
        if not self._token_revocation_list_fetched_time_prop:
            # If the fetched list has been written to disk, use its
            # modification time.
            if os.path.exists(self._revoked_file_name):
                mtime = os.path.getmtime(self._revoked_file_name)
                fetched_time = datetime.datetime.utcfromtimestamp(mtime)
            # Otherwise the list will need to be fetched.
            else:
                fetched_time = datetime.datetime.min
            self._token_revocation_list_fetched_time_prop = fetched_time
        return self._token_revocation_list_fetched_time_prop

    @_token_revocation_list_fetched_time.setter
    def _token_revocation_list_fetched_time(self, value):
        self._token_revocation_list_fetched_time_prop = value

    @property
    def _token_revocation_list(self):
        timeout = (self._token_revocation_list_fetched_time +
                   self._token_revocation_list_cache_timeout)
        list_is_current = timeutils.utcnow() < timeout

        if list_is_current:
            # Load the list from disk if required
            if not self._token_revocation_list_prop:
                open_kwargs = {'encoding': 'utf-8'} if six.PY3 else {}
                with open(self._revoked_file_name, 'r', **open_kwargs) as f:
                    self._token_revocation_list_prop = jsonutils.loads(
                        f.read())
        else:
            self._token_revocation_list = self._fetch_revocation_list()
        return self._token_revocation_list_prop

    def _atomic_write_to_signing_dir(self, file_name, value):
        # In Python2, encoding is slow so the following check avoids it if it
        # is not absolutely necessary.
        if isinstance(value, six.text_type):
            value = value.encode('utf-8')

        def _atomic_write(destination, data):
            with tempfile.NamedTemporaryFile(dir=self._signing_dirname,
                                             delete=False) as f:
                f.write(data)
            os.rename(f.name, destination)

        try:
            _atomic_write(file_name, value)
        except (OSError, IOError):
            self._verify_signing_dir()
            _atomic_write(file_name, value)

    @_token_revocation_list.setter
    def _token_revocation_list(self, value):
        """Save a revocation list to memory and to disk.

        :param value: A json-encoded revocation list

        """
        self._token_revocation_list_prop = jsonutils.loads(value)
        self._token_revocation_list_fetched_time = timeutils.utcnow()
        self._atomic_write_to_signing_dir(self._revoked_file_name, value)

    def _fetch_revocation_list(self):
        revocation_list_data = self._identity_server.fetch_revocation_list()
        return self._cms_verify(revocation_list_data)

    def _fetch_signing_cert(self):
        self._atomic_write_to_signing_dir(
            self._signing_cert_file_name,
            self._identity_server.fetch_signing_cert())

    def _fetch_ca_cert(self):
        self._atomic_write_to_signing_dir(
            self._signing_ca_file_name,
            self._identity_server.fetch_ca_cert())

    def _create_identity_server(self):
        # NOTE(jamielennox): Loading Session here should be exactly the
        # same as calling Session.load_from_conf_options(CONF, GROUP)
        # however we can't do that because we have to use _conf_get to
        # support the paste.ini options.
        sess = session.Session.construct(dict(
            cert=self._conf_get('certfile'),
            key=self._conf_get('keyfile'),
            cacert=self._conf_get('cafile'),
            insecure=self._conf_get('insecure'),
            timeout=self._conf_get('http_connect_timeout')
        ))

        # NOTE(jamielennox): The original auth mechanism allowed deployers
        # to configure authentication information via paste file. These
        # are accessible via _conf_get, however this doesn't work with the
        # plugin loading mechanisms. For using auth plugins we only support
        # configuring via the CONF file.
        auth_plugin = auth.load_from_conf_options(CONF, _AUTHTOKEN_GROUP)

        if not auth_plugin:
            # NOTE(jamielennox): Loading AuthTokenPlugin here should be
            # exactly the same as calling
            # _AuthTokenPlugin.load_from_conf_options(CONF, GROUP) however
            # we can't do that because we have to use _conf_get to support
            # the paste.ini options.
            auth_plugin = _AuthTokenPlugin.load_from_options(
                auth_host=self._conf_get('auth_host'),
                auth_port=int(self._conf_get('auth_port')),
                auth_protocol=self._conf_get('auth_protocol'),
                auth_admin_prefix=self._conf_get('auth_admin_prefix'),
                admin_user=self._conf_get('admin_user'),
                admin_password=self._conf_get('admin_password'),
                admin_tenant_name=self._conf_get('admin_tenant_name'),
                admin_token=self._conf_get('admin_token'),
                identity_uri=self._conf_get('identity_uri'),
                log=self._LOG)

        adap = adapter.Adapter(
            sess,
            auth=auth_plugin,
            service_type='identity',
            interface='admin',
            connect_retries=self._conf_get('http_request_max_retries'))

        auth_version = self._conf_get('auth_version')
        if auth_version is not None:
            auth_version = discover.normalize_version_number(auth_version)
        return _IdentityServer(
            self._LOG,
            adap,
            include_service_catalog=self._include_service_catalog,
            requested_auth_version=auth_version)

    def _token_cache_factory(self):
        security_strategy = self._conf_get('memcache_security_strategy')

        cache_kwargs = dict(
            cache_time=int(self._conf_get('token_cache_time')),
            hash_algorithms=self._conf_get('hash_algorithms'),
            env_cache_name=self._conf_get('cache'),
            memcached_servers=self._conf_get('memcached_servers'),
            use_advanced_pool=self._conf_get('memcache_use_advanced_pool'),
            memcache_pool_dead_retry=self._conf_get(
                'memcache_pool_dead_retry'),
            memcache_pool_maxsize=self._conf_get('memcache_pool_maxsize'),
            memcache_pool_unused_timeout=self._conf_get(
                'memcache_pool_unused_timeout'),
            memcache_pool_conn_get_timeout=self._conf_get(
                'memcache_pool_conn_get_timeout'),
            memcache_pool_socket_timeout=self._conf_get(
                'memcache_pool_socket_timeout'),
        )

        if security_strategy:
            return _SecureTokenCache(self._LOG,
                                     security_strategy,
                                     self._conf_get('memcache_secret_key'),
                                     **cache_kwargs)
        else:
            return _TokenCache(self._LOG, **cache_kwargs)


class _CachePool(list):
    """A lazy pool of cache references."""

    def __init__(self, cache, memcached_servers):
        self._environment_cache = cache
        self._memcached_servers = memcached_servers

    @contextlib.contextmanager
    def reserve(self):
        """Context manager to manage a pooled cache reference."""
        if self._environment_cache is not None:
            # skip pooling and just use the cache from the upstream filter
            yield self._environment_cache
            return  # otherwise the context manager will continue!

        try:
            c = self.pop()
        except IndexError:
            # the pool is empty, so we need to create a new client
            c = memorycache.get_client(self._memcached_servers)

        try:
            yield c
        finally:
            self.append(c)


class _MemcacheClientPool(object):
    """An advanced memcached client pool that is eventlet safe."""
    def __init__(self, memcache_servers, memcache_dead_retry=None,
                 memcache_pool_maxsize=None, memcache_pool_unused_timeout=None,
                 memcache_pool_conn_get_timeout=None,
                 memcache_pool_socket_timeout=None):
        # NOTE(morganfainberg): import here to avoid hard dependency on
        # python-memcache library.
        global _memcache_pool
        from keystonemiddleware import _memcache_pool

        self._pool = _memcache_pool.MemcacheClientPool(
            memcache_servers,
            arguments={
                'dead_retry': memcache_dead_retry,
                'socket_timeout': memcache_pool_socket_timeout,
            },
            maxsize=memcache_pool_maxsize,
            unused_timeout=memcache_pool_unused_timeout,
            conn_get_timeout=memcache_pool_conn_get_timeout,
        )

    @contextlib.contextmanager
    def reserve(self):
        with self._pool.get() as client:
            yield client


class _IdentityServer(object):
    """Base class for operations on the Identity API server.

    The auth_token middleware needs to communicate with the Identity API server
    to validate UUID tokens, fetch the revocation list, signing certificates,
    etc. This class encapsulates the data and methods to perform these
    operations.

    """

    def __init__(self, log, adap, include_service_catalog=None,
                 requested_auth_version=None):
        self._LOG = log
        self._adapter = adap
        self._include_service_catalog = include_service_catalog
        self._requested_auth_version = requested_auth_version

        # Built on-demand with self._request_strategy.
        self._request_strategy_obj = None

    @property
    def auth_uri(self):
        auth_uri = self._adapter.get_endpoint(interface=auth.AUTH_INTERFACE)

        # NOTE(jamielennox): This weird stripping of the prefix hack is
        # only relevant to the legacy case. We urljoin '/' to get just the
        # base URI as this is the original behaviour.
        if isinstance(self._adapter.auth, _AuthTokenPlugin):
            auth_uri = urllib.parse.urljoin(auth_uri, '/').rstrip('/')

        return auth_uri

    @property
    def auth_version(self):
        return self._request_strategy.AUTH_VERSION

    @property
    def _request_strategy(self):
        if not self._request_strategy_obj:
            strategy_class = self._get_strategy_class()
            self._adapter.version = strategy_class.AUTH_VERSION

            self._request_strategy_obj = strategy_class(
                self._json_request,
                self._adapter,
                include_service_catalog=self._include_service_catalog)

        return self._request_strategy_obj

    def _get_strategy_class(self):
        if self._requested_auth_version:
            # A specific version was requested.
            if discover.version_match(_V3RequestStrategy.AUTH_VERSION,
                                      self._requested_auth_version):
                return _V3RequestStrategy

            # The version isn't v3 so we don't know what to do. Just assume V2.
            return _V2RequestStrategy

        # Specific version was not requested then we fall through to
        # discovering available versions from the server
        for klass in _REQUEST_STRATEGIES:
            if self._adapter.get_endpoint(version=klass.AUTH_VERSION):
                msg = _LI('Auth Token confirmed use of %s apis')
                self._LOG.info(msg, self._requested_auth_version)
                return klass

        versions = ['v%d.%d' % s.AUTH_VERSION for s in _REQUEST_STRATEGIES]
        self._LOG.error(_LE('No attempted versions [%s] supported by server'),
                        ', '.join(versions))

        msg = _('No compatible apis supported by server')
        raise ServiceError(msg)

    def verify_token(self, user_token, retry=True):
        """Authenticate user token with identity server.

        :param user_token: user's token id
        :param retry: flag that forces the middleware to retry
                      user authentication when an indeterminate
                      response is received. Optional.
        :returns: token object received from identity server on success
        :raises InvalidToken: if token is rejected
        :raises ServiceError: if unable to authenticate token

        """
        user_token = _safe_quote(user_token)

        try:
            response, data = self._request_strategy.verify_token(user_token)
        except exceptions.NotFound as e:
            self._LOG.warn(_LW('Authorization failed for token'))
            self._LOG.warn(_LW('Identity response: %s'), e.response.text)
        except exceptions.Unauthorized as e:
            self._LOG.info(_LI('Identity server rejected authorization'))
            self._LOG.warn(_LW('Identity response: %s'), e.response.text)
            if retry:
                self._LOG.info(_LI('Retrying validation'))
                return self.verify_token(user_token, False)
        except exceptions.HttpError as e:
            self._LOG.error(
                _LE('Bad response code while validating token: %s'),
                e.http_status)
            self._LOG.warn(_LW('Identity response: %s'), e.response.text)
        else:
            if response.status_code == 200:
                return data

            raise InvalidToken()

    def fetch_revocation_list(self):
        try:
            response, data = self._json_request(
                'GET', '/tokens/revoked',
                authenticated=True,
                endpoint_filter={'version': (2, 0)})
        except exceptions.HTTPError as e:
            raise RevocationListError(_('Failed to fetch token revocation '
                                        'list: %d') % e.http_status)
        if response.status_code != 200:
            raise RevocationListError(_('Unable to fetch token revocation '
                                        'list.'))
        if 'signed' not in data:
            raise RevocationListError(_('Revocation list improperly '
                                        'formatted.'))
        return data['signed']

    def fetch_signing_cert(self):
        return self._fetch_cert_file('signing')

    def fetch_ca_cert(self):
        return self._fetch_cert_file('ca')

    def _json_request(self, method, path, **kwargs):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param **kwargs: additional parameters used by session or endpoint
        :returns: http response object, response body parsed as json
        :raises ServerError: when unable to communicate with identity server.

        """
        headers = kwargs.setdefault('headers', {})
        headers['Accept'] = 'application/json'

        response = self._adapter.request(path, method, **kwargs)

        try:
            data = jsonutils.loads(response.text)
        except ValueError:
            self._LOG.debug('Identity server did not return json-encoded body')
            data = {}

        return response, data

    def _fetch_cert_file(self, cert_type):
        try:
            response = self._request_strategy.fetch_cert_file(cert_type)
        except exceptions.HTTPError as e:
            raise exceptions.CertificateConfigError(e.details)
        if response.status_code != 200:
            raise exceptions.CertificateConfigError(response.text)
        return response.text


class _RequestStrategy(object):

    AUTH_VERSION = None

    def __init__(self, json_request, adap, include_service_catalog=None):
        self._json_request = json_request
        self._adapter = adap
        self._include_service_catalog = include_service_catalog

    def verify_token(self, user_token):
        pass

    def fetch_cert_file(self, cert_type):
        pass


class _V2RequestStrategy(_RequestStrategy):

    AUTH_VERSION = (2, 0)

    def verify_token(self, user_token):
        return self._json_request('GET',
                                  '/tokens/%s' % user_token,
                                  authenticated=True)

    def fetch_cert_file(self, cert_type):
        return self._adapter.get('/certificates/%s' % cert_type,
                                 authenticated=False)


class _V3RequestStrategy(_RequestStrategy):

    AUTH_VERSION = (3, 0)

    def verify_token(self, user_token):
        path = '/auth/tokens'
        if not self._include_service_catalog:
            path += '?nocatalog'

        return self._json_request('GET',
                                  path,
                                  authenticated=True,
                                  headers={'X-Subject-Token': user_token})

    def fetch_cert_file(self, cert_type):
        if cert_type == 'signing':
            cert_type = 'certificates'

        return self._adapter.get('/OS-SIMPLE-CERT/%s' % cert_type,
                                 authenticated=False)


# NOTE(jamielennox): must be defined after request strategy classes
_REQUEST_STRATEGIES = [_V3RequestStrategy, _V2RequestStrategy]


class _TokenCache(object):
    """Encapsulates the auth_token token cache functionality.

    auth_token caches tokens that it's seen so that when a token is re-used the
    middleware doesn't have to do a more expensive operation (like going to the
    identity server) to validate the token.

    initialize() must be called before calling the other methods.

    Store a valid token in the cache using store(); mark a token as invalid in
    the cache using store_invalid().

    Check if a token is in the cache and retrieve it using get().

    """

    _CACHE_KEY_TEMPLATE = 'tokens/%s'
    _INVALID_INDICATOR = 'invalid'

    def __init__(self, log, cache_time=None, hash_algorithms=None,
                 env_cache_name=None, memcached_servers=None,
                 use_advanced_pool=False, memcache_pool_dead_retry=None,
                 memcache_pool_maxsize=None, memcache_pool_unused_timeout=None,
                 memcache_pool_conn_get_timeout=None,
                 memcache_pool_socket_timeout=None):
        self._LOG = log
        self._cache_time = cache_time
        self._hash_algorithms = hash_algorithms
        self._env_cache_name = env_cache_name
        self._memcached_servers = memcached_servers
        self._use_advanced_pool = use_advanced_pool
        self._memcache_pool_dead_retry = memcache_pool_dead_retry,
        self._memcache_pool_maxsize = memcache_pool_maxsize,
        self._memcache_pool_unused_timeout = memcache_pool_unused_timeout
        self._memcache_pool_conn_get_timeout = memcache_pool_conn_get_timeout
        self._memcache_pool_socket_timeout = memcache_pool_socket_timeout

        self._cache_pool = None
        self._initialized = False

    def _get_cache_pool(self, cache, memcache_servers, use_advanced_pool=False,
                        memcache_dead_retry=None, memcache_pool_maxsize=None,
                        memcache_pool_unused_timeout=None,
                        memcache_pool_conn_get_timeout=None,
                        memcache_pool_socket_timeout=None):
        if use_advanced_pool is True and memcache_servers and cache is None:
            return _MemcacheClientPool(
                memcache_servers,
                memcache_dead_retry=memcache_dead_retry,
                memcache_pool_maxsize=memcache_pool_maxsize,
                memcache_pool_unused_timeout=memcache_pool_unused_timeout,
                memcache_pool_conn_get_timeout=memcache_pool_conn_get_timeout,
                memcache_pool_socket_timeout=memcache_pool_socket_timeout)
        else:
            return _CachePool(cache, memcache_servers)

    def initialize(self, env):
        if self._initialized:
            return

        self._cache_pool = self._get_cache_pool(
            env.get(self._env_cache_name),
            self._memcached_servers,
            use_advanced_pool=self._use_advanced_pool,
            memcache_dead_retry=self._memcache_pool_dead_retry,
            memcache_pool_maxsize=self._memcache_pool_maxsize,
            memcache_pool_unused_timeout=self._memcache_pool_unused_timeout,
            memcache_pool_conn_get_timeout=self._memcache_pool_conn_get_timeout
        )

        self._initialized = True

    def get(self, user_token):
        """Check if the token is cached already.

        Returns a tuple. The first element is a list of token IDs, where the
        first one is the preferred hash.

        The second element is the token data from the cache if the token was
        cached, otherwise ``None``.

        :raises InvalidToken: if the token is invalid

        """

        if cms.is_asn1_token(user_token) or cms.is_pkiz(user_token):
            # user_token is a PKI token that's not hashed.

            token_hashes = list(cms.cms_hash_token(user_token, mode=algo)
                                for algo in self._hash_algorithms)

            for token_hash in token_hashes:
                cached = self._cache_get(token_hash)
                if cached:
                    return (token_hashes, cached)

            # The token wasn't found using any hash algorithm.
            return (token_hashes, None)

        # user_token is either a UUID token or a hashed PKI token.
        token_id = user_token
        cached = self._cache_get(token_id)
        return ([token_id], cached)

    def store(self, token_id, data, expires):
        """Put token data into the cache.

        Stores the parsed expire date in cache allowing
        quick check of token freshness on retrieval.

        """
        self._LOG.debug('Storing token in cache')
        self._cache_store(token_id, (data, expires))

    def store_invalid(self, token_id):
        """Store invalid token in cache."""
        self._LOG.debug('Marking token as unauthorized in cache')
        self._cache_store(token_id, self._INVALID_INDICATOR)

    def _get_cache_key(self, token_id):
        """Get a unique key for this token id.

        Turn the token_id into something that can uniquely identify that token
        in a key value store.

        As this is generally the first function called in a key lookup this
        function also returns a context object. This context object is not
        modified or used by the Cache object but is passed back on subsequent
        functions so that decryption or other data can be shared throughout a
        cache lookup.

        :param str token_id: The unique token id.

        :returns: A tuple of a string key and an implementation specific
                  context object
        """
        # NOTE(jamielennox): in the basic implementation there is no need for
        # a context so just pass None as it will only get passed back later.
        unused_context = None
        return self._CACHE_KEY_TEMPLATE % token_id, unused_context

    def _deserialize(self, data, context):
        """Deserialize data from the cache back into python objects.

        Take data retrieved from the cache and return an appropriate python
        dictionary.

        :param str data: The data retrieved from the cache.
        :param object context: The context that was returned from
                               _get_cache_key.

        :returns: The python object that was saved.
        """
        # memory cache will handle deserialization for us
        return data

    def _serialize(self, data, context):
        """Serialize data so that it can be saved to the cache.

        Take python objects and serialize them so that they can be saved into
        the cache.

        :param object data: The data to be cached.
        :param object context: The context that was returned from
                               _get_cache_key.

        :returns: The python object that was saved.
        """
        # memory cache will handle serialization for us
        return data

    def _cache_get(self, token_id):
        """Return token information from cache.

        If token is invalid raise InvalidToken
        return token only if fresh (not expired).
        """

        if not token_id:
            # Nothing to do
            return

        key, context = self._get_cache_key(token_id)

        with self._cache_pool.reserve() as cache:
            serialized = cache.get(key)

        if serialized is None:
            return None

        data = self._deserialize(serialized, context)

        # Note that _INVALID_INDICATOR and (data, expires) are the only
        # valid types of serialized cache entries, so there is not
        # a collision with jsonutils.loads(serialized) == None.
        if not isinstance(data, six.string_types):
            data = data.decode('utf-8')
        cached = jsonutils.loads(data)
        if cached == self._INVALID_INDICATOR:
            self._LOG.debug('Cached Token is marked unauthorized')
            raise InvalidToken(_('Token authorization failed'))

        data, expires = cached

        try:
            expires = timeutils.parse_isotime(expires)
        except ValueError:
            # Gracefully handle upgrade of expiration times from *nix
            # timestamps to ISO 8601 formatted dates by ignoring old cached
            # values.
            return

        expires = timeutils.normalize_time(expires)
        utcnow = timeutils.utcnow()
        if utcnow < expires:
            self._LOG.debug('Returning cached token')
            return data
        else:
            self._LOG.debug('Cached Token seems expired')
            raise InvalidToken(_('Token authorization failed'))

    def _cache_store(self, token_id, data):
        """Store value into memcache.

        data may be _INVALID_INDICATOR or a tuple like (data, expires)

        """
        data = jsonutils.dumps(data)
        if isinstance(data, six.text_type):
            data = data.encode('utf-8')

        cache_key, context = self._get_cache_key(token_id)
        data_to_store = self._serialize(data, context)

        with self._cache_pool.reserve() as cache:
            cache.set(cache_key, data_to_store, time=self._cache_time)


class _SecureTokenCache(_TokenCache):
    """A token cache that stores tokens encrypted.

    A more secure version of _TokenCache that will encrypt tokens before
    caching them.
    """

    def __init__(self, log, security_strategy, secret_key, **kwargs):
        super(_SecureTokenCache, self).__init__(log, **kwargs)

        security_strategy = security_strategy.upper()

        if security_strategy not in ('MAC', 'ENCRYPT'):
            raise ConfigurationError(_('memcache_security_strategy must be '
                                       'ENCRYPT or MAC'))
        if not secret_key:
            raise ConfigurationError(_('memcache_secret_key must be defined '
                                       'when a memcache_security_strategy '
                                       'is defined'))

        if isinstance(security_strategy, six.string_types):
            security_strategy = security_strategy.encode('utf-8')
        if isinstance(secret_key, six.string_types):
            secret_key = secret_key.encode('utf-8')

        self._security_strategy = security_strategy
        self._secret_key = secret_key

    def _get_cache_key(self, token_id):
        context = memcache_crypt.derive_keys(token_id,
                                             self._secret_key,
                                             self._security_strategy)
        key = self._CACHE_KEY_TEMPLATE % memcache_crypt.get_cache_key(context)
        return key, context

    def _deserialize(self, data, context):
        try:
            # unprotect_data will return None if raw_cached is None
            return memcache_crypt.unprotect_data(context, data)
        except Exception:
            msg = _LE('Failed to decrypt/verify cache data')
            self._LOG.exception(msg)

        # this should have the same effect as data not
        # found in cache
        return None

    def _serialize(self, data, context):
        return memcache_crypt.protect_data(context, data)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)


if __name__ == '__main__':
    def echo_app(environ, start_response):
        """A WSGI application that echoes the CGI environment to the user."""
        start_response('200 OK', [('Content-Type', 'application/json')])
        environment = dict((k, v) for k, v in six.iteritems(environ)
                           if k.startswith('HTTP_X_'))
        yield jsonutils.dumps(environment)

    from wsgiref import simple_server

    # hardcode any non-default configuration here
    conf = {'auth_protocol': 'http', 'admin_token': 'ADMIN'}
    app = AuthProtocol(echo_app, conf)
    server = simple_server.make_server('', 8000, app)
    print('Serving on port 8000 (Ctrl+C to end)...')
    server.serve_forever()
