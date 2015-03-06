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

HTTP_X_IDENTITY_STATUS, HTTP_X_SERVICE_IDENTITY_STATUS
    'Confirmed' or 'Invalid'
    The underlying service will only see a value of 'Invalid' if the Middleware
    is configured to run in 'delay_auth_decision' mode. As with all such
    headers, HTTP_X_SERVICE_IDENTITY_STATUS will only exist in the
    environment if a service token is presented. This is different than
    HTTP_X_IDENTITY_STATUS which is always set even if no user token is
    presented. This allows the underlying service to determine if a
    denial should use 401 or 403.

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

import datetime
import logging

from keystoneclient import access
from keystoneclient import adapter
from keystoneclient import auth
from keystoneclient.common import cms
from keystoneclient import discover
from keystoneclient import exceptions
from keystoneclient import session
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six

from keystonemiddleware.auth_token import _auth
from keystonemiddleware.auth_token import _base
from keystonemiddleware.auth_token import _cache
from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _identity
from keystonemiddleware.auth_token import _revocations
from keystonemiddleware.auth_token import _signing_dir
from keystonemiddleware.auth_token import _user_plugin
from keystonemiddleware.auth_token import _utils
from keystonemiddleware.i18n import _, _LC, _LE, _LI, _LW


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

CONF = cfg.CONF
CONF.register_opts(_OPTS, group=_base.AUTHTOKEN_GROUP)

_LOG = logging.getLogger(__name__)

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
        raise exc.InvalidToken(_('Token authorization failed'))
    if _token_is_v2(data):
        return data['access']['token']['expires']
    elif _token_is_v3(data):
        return data['token']['expires_at']
    else:
        raise exc.InvalidToken(_('Token authorization failed'))


def _confirm_token_not_expired(expires):
    expires = timeutils.parse_isotime(expires)
    expires = timeutils.normalize_time(expires)
    utcnow = timeutils.utcnow()
    if utcnow >= expires:
        raise exc.InvalidToken(_('Token authorization failed'))


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


def _conf_values_type_convert(conf):
    """Convert conf values into correct type."""
    if not conf:
        return {}

    opt_types = {}
    for o in (_OPTS + _auth.AuthTokenPlugin.get_options()):
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
            raise exc.ConfigurationError(
                _('Unable to convert the value of %(key)s option into correct '
                  'type: %(ex)s') % {'key': k, 'ex': e})
        opts[dest] = v
    return opts


class AuthProtocol(object):
    """Middleware that handles authenticating client calls."""

    _SIGNING_CERT_FILE_NAME = 'signing_cert.pem'
    _SIGNING_CA_FILE_NAME = 'cacert.pem'

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

        self._signing_directory = _signing_dir.SigningDirectory(
            directory_name=self._conf_get('signing_dir'), log=self._LOG)

        self._token_cache = self._token_cache_factory()

        revocation_cache_timeout = datetime.timedelta(
            seconds=self._conf_get('revocation_cache_time'))
        self._revocations = _revocations.Revocations(revocation_cache_timeout,
                                                     self._signing_directory,
                                                     self._identity_server,
                                                     self._cms_verify,
                                                     self._LOG)

        self._check_revocations_for_cached = self._conf_get(
            'check_revocations_for_cached')
        self._init_auth_headers()

    def _conf_get(self, name, group=_base.AUTHTOKEN_GROUP):
        # try config from paste-deploy first
        if name in self._conf:
            return self._conf[name]
        else:
            return CONF[group][name]

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
            except exc.InvalidToken:
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
            except exc.InvalidToken:
                if self._delay_auth_decision:
                    self._LOG.info(
                        _LI('Invalid service token - deferring reject '
                            'downstream'))
                    self._add_headers(env,
                                      {'X-Service-Identity-Status': 'Invalid'})
                else:
                    self._LOG.info(
                        _LI('Invalid service token - rejecting request'))
                    return self._reject_request(env, start_response)

            env['keystone.token_auth'] = _user_plugin.UserAuthPlugin(
                user_auth_ref, serv_auth_ref)

        except exc.ServiceError as e:
            self._LOG.critical(_LC('Unable to obtain admin token: %s'), e)
            return self._do_503_error(env, start_response)

        self._LOG.debug("Received request from %s", _fmt_msg(env))

        return self._call_app(env, start_response)

    def _do_503_error(self, env, start_response):
        resp = _utils.MiniResp('Service unavailable', env)
        start_response('503 Service Unavailable', resp.headers)
        return resp.body

    def _init_auth_headers(self):
        """Initialize auth header list.

        Both user and service token headers are generated.
        """
        auth_headers = ['X-Service-Catalog',
                        'X-Identity-Status',
                        'X-Service-Identity-Status',
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
        :raises exc.InvalidToken: if no token is provided in request

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
            raise exc.InvalidToken(_('Unable to find token in headers'))

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
        resp = _utils.MiniResp('Authentication required',
                               env, self._reject_auth_headers)
        start_response('401 Unauthorized', resp.headers)
        return resp.body

    def _validate_token(self, token, env, retry=True):
        """Authenticate user token

        :param token: token id
        :param env: wsgi environment
        :param retry: Ignored, as it is not longer relevant
        :returns: uncrypted body of the token if the token is valid
        :raises exc.InvalidToken: if token is rejected

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
                    self._revocations.check(token_ids)
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
                except exc.RevocationListError:
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
            raise exc.InvalidToken(_('Token authorization failed'))
        except exc.ServiceError:
            raise
        except Exception:
            self._LOG.debug('Token validation failure.', exc_info=True)
            if token_id:
                self._token_cache.store_invalid(token_id)
            self._LOG.warn(_LW('Authorization failed for token'))
            raise exc.InvalidToken(_('Token authorization failed'))

    def _build_user_headers(self, auth_ref, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by identity
                           server on authentication
        :raises exc.InvalidToken: when unable to parse token object

        """
        roles = ','.join(auth_ref.role_names)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise exc.InvalidToken(_('Unable to determine tenancy.'))

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
        :raises exc.InvalidToken: when unable to parse token object

        """
        auth_ref = access.AccessInfo.factory(body=token_info)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise exc.InvalidToken(_('Unable to determine service tenancy.'))

        roles = ','.join(auth_ref.role_names)
        rval = {
            'X-Service-Identity-Status': 'Confirmed',
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

        raise exc.InvalidToken(msg)

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

    def _cms_verify(self, data, inform=cms.PKI_ASN1_FORM):
        """Verifies the signature of the provided data's IAW CMS syntax.

        If either of the certificate files might be missing, fetch them and
        retry.
        """
        def verify():
            try:
                signing_cert_path = self._signing_directory.calc_path(
                    self._SIGNING_CERT_FILE_NAME)
                signing_ca_path = self._signing_directory.calc_path(
                    self._SIGNING_CA_FILE_NAME)
                return cms.cms_verify(data, signing_cert_path,
                                      signing_ca_path,
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
        self._revocations.check(token_ids)
        formatted = cms.token_to_cms(signed_text)
        verified = self._cms_verify(formatted)
        return verified

    def _verify_pkiz_token(self, signed_text, token_ids):
        self._revocations.check(token_ids)
        try:
            uncompressed = cms.pkiz_uncompress(signed_text)
            verified = self._cms_verify(uncompressed, inform=cms.PKIZ_CMS_FORM)
            return verified
        # TypeError If the signed_text is not zlib compressed
        except TypeError:
            raise exc.InvalidToken(signed_text)

    def _fetch_signing_cert(self):
        self._signing_directory.write_file(
            self._SIGNING_CERT_FILE_NAME,
            self._identity_server.fetch_signing_cert())

    def _fetch_ca_cert(self):
        self._signing_directory.write_file(
            self._SIGNING_CA_FILE_NAME,
            self._identity_server.fetch_ca_cert())

    def _get_auth_plugin(self):
        # NOTE(jamielennox): Ideally this would use get_from_conf_options
        # however that is not possible because we have to support the override
        # pattern we use in _conf_get. There is a somewhat replacement for this
        # in keystoneclient in load_from_options_getter which should be used
        # when available. Until then this is essentially a copy and paste of
        # the ksc load_from_conf_options code because we need to get a fix out
        # for this quickly.

        # FIXME(jamielennox): update to use load_from_options_getter when
        # https://review.openstack.org/162529 merges.

        # !!! - UNDER NO CIRCUMSTANCES COPY ANY OF THIS CODE - !!!

        group = self._conf_get('auth_section') or _base.AUTHTOKEN_GROUP
        plugin_name = self._conf_get('auth_plugin', group=group)
        plugin_kwargs = dict()

        if plugin_name:
            plugin_class = auth.get_plugin_class(plugin_name)
        else:
            plugin_class = _auth.AuthTokenPlugin
            # logger object is a required parameter of the default plugin
            plugin_kwargs['log'] = self._LOG

        plugin_opts = plugin_class.get_options()
        CONF.register_opts(plugin_opts, group=group)

        for opt in plugin_opts:
            val = self._conf_get(opt.dest, group=group)
            if val is not None:
                val = opt.type(val)
            plugin_kwargs[opt.dest] = val

        return plugin_class.load_from_options(**plugin_kwargs)

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

        auth_plugin = self._get_auth_plugin()

        adap = adapter.Adapter(
            sess,
            auth=auth_plugin,
            service_type='identity',
            interface='admin',
            connect_retries=self._conf_get('http_request_max_retries'))

        auth_version = self._conf_get('auth_version')
        if auth_version is not None:
            auth_version = discover.normalize_version_number(auth_version)
        return _identity.IdentityServer(
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
            secret_key = self._conf_get('memcache_secret_key')
            return _cache.SecureTokenCache(self._LOG,
                                           security_strategy,
                                           secret_key,
                                           **cache_kwargs)
        else:
            return _cache.TokenCache(self._LOG, **cache_kwargs)


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


# NOTE(jamielennox): Maintained here for public API compatibility.
InvalidToken = exc.InvalidToken
ServiceError = exc.ServiceError
ConfigurationError = exc.ConfigurationError
RevocationListError = exc.RevocationListError
