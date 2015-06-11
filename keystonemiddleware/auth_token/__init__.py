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


Configuration
-------------

Middleware configuration can be in the main application's configuration file,
e.g. in ``nova.conf``:

.. code-block:: ini

  [keystone_authtoken]
  auth_plugin = password
  auth_url = http://keystone:35357/
  username = nova
  user_domain_id = default
  password = whyarewestillusingpasswords
  project_name = service
  project_domain_id = default

Configuration can also be in the ``api-paste.ini`` file with the same options,
but this is discouraged.

Swift
-----

When deploy Keystone auth_token middleware with Swift, user may elect to use
Swift memcache instead of the local auth_token memcache. Swift memcache is
passed in from the request environment and it's identified by the
``swift.cache`` key. However it could be different, depending on deployment. To
use Swift memcache, you must set the ``cache`` option to the environment key
where the Swift cache object is stored.

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
import six
import webob.dec

from keystonemiddleware.auth_token import _auth
from keystonemiddleware.auth_token import _base
from keystonemiddleware.auth_token import _cache
from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _identity
from keystonemiddleware.auth_token import _request
from keystonemiddleware.auth_token import _revocations
from keystonemiddleware.auth_token import _signing_dir
from keystonemiddleware.auth_token import _user_plugin
from keystonemiddleware.i18n import _, _LC, _LE, _LI, _LW


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
                    'with a memcached server.'),
    cfg.IntOpt('memcache_pool_unused_timeout',
               default=60,
               help='(Optional) Number of seconds a connection to memcached'
               ' is held unused in the pool before it is closed.'),
    cfg.IntOpt('memcache_pool_conn_get_timeout',
               default=10,
               help='(Optional) Number of seconds that an operation will wait '
                    'to get a memcached client connection from the pool.'),
    cfg.BoolOpt('memcache_use_advanced_pool',
                default=False,
                help='(Optional) Use the advanced (eventlet safe) memcached '
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
        self._hash_algorithms = self._conf_get('hash_algorithms')

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

    def _conf_get(self, name, group=_base.AUTHTOKEN_GROUP):
        # try config from paste-deploy first
        if name in self._conf:
            return self._conf[name]
        else:
            return CONF[group][name]

    @webob.dec.wsgify(RequestClass=_request._AuthTokenRequest)
    def __call__(self, request):
        """Handle incoming request.

        Authenticate send downstream on success. Reject request if
        we can't authenticate.

        """
        self._token_cache.initialize(request.environ)
        request.remove_auth_headers()

        try:
            user_auth_ref = None
            serv_auth_ref = None

            try:
                self._LOG.debug('Authenticating user token')
                user_token_info = self._get_user_token_from_request(request)
                user_auth_ref, user_token_info = self._validate_token(
                    user_token_info, request.environ)
                request.environ['keystone.token_info'] = user_token_info
                request.set_user_headers(user_auth_ref,
                                         self._include_service_catalog)
            except exc.InvalidToken:
                if self._delay_auth_decision:
                    self._LOG.info(
                        _LI('Invalid user token - deferring reject '
                            'downstream'))
                    request.headers['X-Identity-Status'] = 'Invalid'
                else:
                    self._LOG.info(
                        _LI('Invalid user token - rejecting request'))
                    self._reject_request()

            try:
                self._LOG.debug('Authenticating service token')
                serv_token = request.headers.get('X-Service-Token')
                if serv_token is not None:
                    serv_auth_ref, serv_token_info = self._validate_token(
                        serv_token, request.environ)
                    request.set_service_headers(serv_auth_ref)
            except exc.InvalidToken:
                if self._delay_auth_decision:
                    self._LOG.info(
                        _LI('Invalid service token - deferring reject '
                            'downstream'))
                    request.headers['X-Service-Identity-Status'] = 'Invalid'
                else:
                    self._LOG.info(
                        _LI('Invalid service token - rejecting request'))
                    self._reject_request()

            p = _user_plugin.UserAuthPlugin(user_auth_ref, serv_auth_ref)
            request.environ['keystone.token_auth'] = p

        except exc.ServiceError as e:
            self._LOG.critical(_LC('Unable to obtain admin token: %s'), e)
            raise webob.exc.HTTPServiceUnavailable()

        if self._LOG.isEnabledFor(logging.DEBUG):
            self._LOG.debug('Received request from %s' % p._log_format)

        response = request.get_response(self._app)

        if response.status_int == 401:
            response.headers.extend(self._reject_auth_headers)

        return response

    def _get_user_token_from_request(self, request):
        """Get token id from request.

        :param env: wsgi request environment
        :returns: token id
        :raises exc.InvalidToken: if no token is provided in request

        """
        token = request.headers.get('X-Auth-Token',
                                    request.headers.get('X-Storage-Token'))
        if token:
            return token
        else:
            if not self._delay_auth_decision:
                self._LOG.debug('Headers: %s', dict(request.headers))
            raise exc.InvalidToken(_('Unable to find token in headers'))

    @property
    def _reject_auth_headers(self):
        header_val = 'Keystone uri=\'%s\'' % self._auth_uri
        return [('WWW-Authenticate', header_val)]

    def _reject_request(self):
        """Redirect client to auth server.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns: HTTPUnauthorized http response

        """
        raise webob.exc.HTTPUnauthorized(body='Authentication required',
                                         headers=self._reject_auth_headers)

    def _token_hashes(self, token):
        """Generate a list of hashes that the current token may be cached as.

        With PKI tokens we have multiple hashing algorithms that we test with
        revocations. This generates that whole list.

        The first element of this list is the preferred algorithm and is what
        new cache values should be saved as.

        :param str token: The token being presented by a user.

        :returns: list of str token hashes.
        """
        if cms.is_asn1_token(token) or cms.is_pkiz(token):
            return list(cms.cms_hash_token(token, mode=algo)
                        for algo in self._hash_algorithms)
        else:
            return [token]

    def _cache_get_hashes(self, token_hashes):
        """Check if the token is cached already.

        Functions takes a list of hashes that might be in the cache and matches
        the first one that is present. If nothing is found in the cache it
        returns None.

        :returns: token data if found else None.
        """

        for token in token_hashes:
            cached = self._token_cache.get(token)

            if cached:
                return cached

    def _validate_token(self, token, env):
        """Authenticate user token

        :param token: token id
        :param env: wsgi environment
        :returns: uncrypted body of the token if the token is valid
        :raises exc.InvalidToken: if token is rejected

        """
        token_hashes = None

        try:
            token_hashes = self._token_hashes(token)
            cached = self._cache_get_hashes(token_hashes)

            if cached:
                data = cached

                if self._check_revocations_for_cached:
                    # A token stored in Memcached might have been revoked
                    # regardless of initial mechanism used to validate it,
                    # and needs to be checked.
                    self._revocations.check(token_hashes)

                auth_ref = access.AccessInfo.factory(body=data,
                                                     auth_token=token)
            else:
                verified = None

                try:
                    if cms.is_pkiz(token):
                        verified = self._verify_pkiz_token(token, token_hashes)
                    elif cms.is_asn1_token(token):
                        verified = self._verify_signed_token(token,
                                                             token_hashes)
                except exceptions.CertificateConfigError:
                    self._LOG.warning(_LW('Fetch certificate config failed, '
                                          'fallback to online validation.'))
                except exc.RevocationListError:
                    self._LOG.warning(_LW('Fetch revocation list failed, '
                                          'fallback to online validation.'))

                if verified is not None:
                    data = jsonutils.loads(verified)
                    auth_ref = access.AccessInfo.factory(body=data,
                                                         auth_token=token)
                else:
                    auth_ref = self._identity_server.verify_token(token)
                    if auth_ref:
                        if auth_ref.version == 'v2.0':
                            data = {'access': auth_ref}
                        else:  # it's v3.
                            data = {'token': auth_ref}
                    else:
                        data = None

            # 0 seconds of validity means is it valid right now.
            if auth_ref.will_expire_soon(stale_duration=0):
                raise exc.InvalidToken(_('Token authorization failed'))

            if _token_is_v2(data) and not auth_ref.project_id:
                msg = _('Unable to determine service tenancy.')
                raise exc.InvalidToken(msg)

            self._confirm_token_bind(data, env)

            if not cached:
                self._token_cache.store(token_hashes[0], data)

            return auth_ref, data
        except (exceptions.ConnectionRefused, exceptions.RequestTimeout):
            self._LOG.debug('Token validation failure.', exc_info=True)
            self._LOG.warning(_LW('Authorization failed for token'))
            raise exc.InvalidToken(_('Token authorization failed'))
        except exc.ServiceError:
            raise
        except Exception:
            self._LOG.debug('Token validation failure.', exc_info=True)
            if token_hashes:
                self._token_cache.store_invalid(token_hashes[0])
            self._LOG.warning(_LW('Authorization failed for token'))
            raise exc.InvalidToken(_('Token authorization failed'))

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


# NOTE(jamielennox): Maintained here for public API compatibility.
InvalidToken = exc.InvalidToken
ServiceError = exc.ServiceError
ConfigurationError = exc.ConfigurationError
RevocationListError = exc.RevocationListError
