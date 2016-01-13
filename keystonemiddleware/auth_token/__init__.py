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
  ``delay_auth_decision`` mode, which means the final decision is delegated to
  the downstream WSGI component (usually the OpenStack service).
* Collects and forwards identity information based on a valid token
  such as user name, domain, project, etc.

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
    to retrieve a new token.

What auth_token adds to the request for use by the OpenStack service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using composite authentication (a user and service token are
present) additional service headers relating to the service user
will be added. They take the same form as the standard headers but add
``_SERVICE_``. These headers will not exist in the environment if no
service token is present.

HTTP_X_IDENTITY_STATUS, HTTP_X_SERVICE_IDENTITY_STATUS
    Will be set to either ``Confirmed`` or ``Invalid``.

    The underlying service will only see a value of 'Invalid' if the middleware
    is configured to run in ``delay_auth_decision`` mode. As with all such
    headers, ``HTTP_X_SERVICE_IDENTITY_STATUS`` will only exist in the
    environment if a service token is presented. This is different than
    ``HTTP_X_IDENTITY_STATUS`` which is always set even if no user token is
    presented. This allows the underlying service to determine if a
    denial should use ``401 Unauthenticated`` or ``403 Forbidden``.

HTTP_X_DOMAIN_ID, HTTP_X_SERVICE_DOMAIN_ID
    Identity service managed unique identifier, string. Only present if
    this is a domain-scoped token.

HTTP_X_DOMAIN_NAME, HTTP_X_SERVICE_DOMAIN_NAME
    Unique domain name, string. Only present if this is a domain-scoped
    token.

HTTP_X_PROJECT_ID, HTTP_X_SERVICE_PROJECT_ID
    Identity service managed unique identifier, string. Only present if
    this is a project-scoped token.

HTTP_X_PROJECT_NAME, HTTP_X_SERVICE_PROJECT_NAME
    Project name, unique within owning domain, string. Only present if
    this is a project-scoped token.

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
    Identity-service managed unique identifier, string.

HTTP_X_USER_NAME, HTTP_X_SERVICE_USER_NAME
    User identifier, unique within owning domain, string.

HTTP_X_USER_DOMAIN_ID, HTTP_X_SERVICE_USER_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    user, string. If this variable is set, this indicates that the USER_NAME
    can only be assumed to be unique within this domain.

HTTP_X_USER_DOMAIN_NAME, HTTP_X_SERVICE_USER_DOMAIN_NAME
    Name of owning domain of user, string. If this variable is set, this
    indicates that the USER_NAME can only be assumed to be unique within
    this domain.

HTTP_X_ROLES, HTTP_X_SERVICE_ROLES
    Comma delimited list of case-sensitive role names.

HTTP_X_SERVICE_CATALOG
    service catalog (optional, JSON string).

    For compatibility reasons this catalog will always be in the V2 catalog
    format even if it is a v3 token.

    .. note:: This is an exception in that it contains 'SERVICE' but relates to
        a user token, not a service token. The existing user's catalog can be
        very large; it was decided not to present a catalog relating to the
        service token to avoid using more HTTP header space.

HTTP_X_TENANT_ID
    *Deprecated* in favor of HTTP_X_PROJECT_ID.

    Identity service managed unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID.

HTTP_X_TENANT_NAME
    *Deprecated* in favor of HTTP_X_PROJECT_NAME.

    Project identifier, unique within owning domain, string. For v3 tokens,
    this will be set to the same value as HTTP_X_PROJECT_NAME.

HTTP_X_TENANT
    *Deprecated* in favor of HTTP_X_TENANT_ID and HTTP_X_TENANT_NAME.

    Identity server-assigned unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID.

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME.

    User name, unique within owning domain, string.

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES.

    Will contain the same values as HTTP_X_ROLES.

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

These variables are set in the request environment for use by the downstream
WSGI component.

keystone.token_info
    Information about the token discovered in the process of validation.  This
    may include extended information returned by the token validation call, as
    well as basic information about the project and user.

keystone.token_auth
    A keystoneauth1 auth plugin that may be used with a
    :py:class:`keystoneauth1.session.Session`. This plugin will load the
    authentication data provided to auth_token middleware.


Configuration
-------------

auth_token middleware configuration can be in the main application's
configuration file, e.g. in ``nova.conf``:

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

When deploy auth_token middleware with Swift, user may elect to use Swift
memcache instead of the local auth_token memcache. Swift memcache is passed in
from the request environment and it's identified by the ``swift.cache`` key.
However it could be different, depending on deployment. To use Swift memcache,
you must set the ``cache`` option to the environment key where the Swift cache
object is stored.

"""

import binascii
import datetime
import logging

from keystoneauth1 import access
from keystoneauth1 import adapter
from keystoneauth1 import discover
from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import loading
from keystoneauth1.loading import session as session_loading
from keystoneclient.common import cms
from keystoneclient import exceptions as ksc_exceptions
from oslo_config import cfg
from oslo_serialization import jsonutils
import pkg_resources
import six
import webob.dec

from keystonemiddleware.auth_token import _auth
from keystonemiddleware.auth_token import _base
from keystonemiddleware.auth_token import _cache
from keystonemiddleware.auth_token import _exceptions as ksm_exceptions
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
    cfg.StrOpt('region_name', default=None,
               help='The region in which the identity server can be found.'),
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
               default='None',
               choices=('None', 'MAC', 'ENCRYPT'),
               ignore_case=True,
               help='(Optional) If defined, indicate whether token data'
               ' should be authenticated or authenticated and encrypted.'
               ' If MAC, token data is authenticated (with HMAC) in the cache.'
               ' If ENCRYPT, token data is encrypted and authenticated in the'
               ' cache. If the value is not one of these options or empty,'
               ' auth_token will raise an exception on initialization.'),
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
    for o in _OPTS + _auth.OPTS:
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
        except KeyError:  # nosec
            # This option is not known to auth_token. v is not converted.
            pass
        except ValueError as e:
            raise ksm_exceptions.ConfigurationError(
                _('Unable to convert the value of %(key)s option into correct '
                  'type: %(ex)s') % {'key': k, 'ex': e})
        opts[dest] = v
    return opts


def _get_project_version(project):
    return pkg_resources.get_distribution(project).version


def _uncompress_pkiz(token):
    # TypeError If the signed_text is not zlib compressed binascii.Error if
    # signed_text has incorrect base64 padding (py34)

    try:
        return cms.pkiz_uncompress(token)
    except (TypeError, binascii.Error):
        raise ksm_exceptions.InvalidToken(token)


class BaseAuthProtocol(object):
    """A base class for AuthProtocol token checking implementations.

    :param Callable app: The next application to call after middleware.
    :param logging.Logger log: The logging object to use for output. By default
                               it will use a logger in the
                               keystonemiddleware.auth_token namespace.
    :param str enforce_token_bind: The style of token binding enforcement to
                                   perform.
    """

    def __init__(self,
                 app,
                 log=_LOG,
                 enforce_token_bind=_BIND_MODE.PERMISSIVE):
        self.log = log
        self._app = app
        self._enforce_token_bind = enforce_token_bind

    @webob.dec.wsgify(RequestClass=_request._AuthTokenRequest)
    def __call__(self, req):
        """Handle incoming request."""
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self._app)
        return self.process_response(response)

    def process_request(self, request):
        """Process request.

        If this method returns a value then that value will be used as the
        response. The next application down the stack will not be executed and
        process_response will not be called.

        Otherwise, the next application down the stack will be executed and
        process_response will be called with the generated response.

        By default this method does not return a value.

        :param request: Incoming request
        :type request: _request.AuthTokenRequest

        """
        user_auth_ref = None
        serv_auth_ref = None

        if request.user_token:
            self.log.debug('Authenticating user token')
            try:
                data, user_auth_ref = self._do_fetch_token(request.user_token)
                self._validate_token(user_auth_ref)
                self._confirm_token_bind(user_auth_ref, request)
            except ksm_exceptions.InvalidToken:
                self.log.info(_LI('Invalid user token'))
                request.user_token_valid = False
            else:
                request.user_token_valid = True
                request.token_info = data

        if request.service_token:
            self.log.debug('Authenticating service token')
            try:
                _, serv_auth_ref = self._do_fetch_token(request.service_token)
                self._validate_token(serv_auth_ref)
                self._confirm_token_bind(serv_auth_ref, request)
            except ksm_exceptions.InvalidToken:
                self.log.info(_LI('Invalid service token'))
                request.service_token_valid = False
            else:
                request.service_token_valid = True

        request.token_auth = _user_plugin.UserAuthPlugin(user_auth_ref,
                                                         serv_auth_ref)

    def _validate_token(self, auth_ref):
        """Perform the validation steps on the token.

        :param auth_ref: The token data
        :type auth_ref: keystoneauth1.access.AccessInfo

        :raises exc.InvalidToken: if token is rejected
        """
        # 0 seconds of validity means it is invalid right now
        if auth_ref.will_expire_soon(stale_duration=0):
            raise ksm_exceptions.InvalidToken(_('Token authorization failed'))

    def _do_fetch_token(self, token):
        """Helper method to fetch a token and convert it into an AccessInfo"""
        data = self.fetch_token(token)

        try:
            return data, access.create(body=data, auth_token=token)
        except Exception:
            self.log.warning(_LW('Invalid token contents.'), exc_info=True)
            raise ksm_exceptions.InvalidToken(_('Token authorization failed'))

    def fetch_token(self, token):
        """Fetch the token data based on the value in the header.

        Retrieve the data associated with the token value that was in the
        header. This can be from PKI, contacting the identity server or
        whatever is required.

        :param str token: The token present in the request header.

        :raises exc.InvalidToken: if token is invalid.

        :returns: The token data
        :rtype: dict
        """
        raise NotImplemented()

    def process_response(self, response):
        """Do whatever you'd like to the response.

        By default the response is returned unmodified.

        :param response: Response object
        :type response: ._request._AuthTokenResponse
        """
        return response

    def _invalid_user_token(self, msg=False):
        # NOTE(jamielennox): use False as the default so that None is valid
        if msg is False:
            msg = _('Token authorization failed')

        raise ksm_exceptions.InvalidToken(msg)

    def _confirm_token_bind(self, auth_ref, req):
        if self._enforce_token_bind == _BIND_MODE.DISABLED:
            return

        # permissive and strict modes don't require there to be a bind
        permissive = self._enforce_token_bind in (_BIND_MODE.PERMISSIVE,
                                                  _BIND_MODE.STRICT)

        if not auth_ref.bind:
            if permissive:
                # no bind provided and none required
                return
            else:
                self.log.info(_LI('No bind information present in token.'))
                self._invalid_user_token()

        # get the named mode if bind_mode is not one of the predefined
        if permissive or self._enforce_token_bind == _BIND_MODE.REQUIRED:
            name = None
        else:
            name = self._enforce_token_bind

        if name and name not in auth_ref.bind:
            self.log.info(_LI('Named bind mode %s not in bind information'),
                          name)
            self._invalid_user_token()

        for bind_type, identifier in six.iteritems(auth_ref.bind):
            if bind_type == _BIND_MODE.KERBEROS:
                if req.auth_type != 'negotiate':
                    self.log.info(_LI('Kerberos credentials required and '
                                      'not present.'))
                    self._invalid_user_token()

                if req.remote_user != identifier:
                    self.log.info(_LI('Kerberos credentials do not match '
                                      'those in bind.'))
                    self._invalid_user_token()

                self.log.debug('Kerberos bind authentication successful.')

            elif self._enforce_token_bind == _BIND_MODE.PERMISSIVE:
                self.log.debug('Ignoring Unknown bind for permissive mode: '
                               '%(bind_type)s: %(identifier)s.',
                               {'bind_type': bind_type,
                                'identifier': identifier})

            else:
                self.log.info(
                    _LI('Couldn`t verify unknown bind: %(bind_type)s: '
                        '%(identifier)s.'),
                    {'bind_type': bind_type, 'identifier': identifier})
                self._invalid_user_token()


class AuthProtocol(BaseAuthProtocol):
    """Middleware that handles authenticating client calls."""

    _SIGNING_CERT_FILE_NAME = 'signing_cert.pem'
    _SIGNING_CA_FILE_NAME = 'cacert.pem'

    def __init__(self, app, conf):
        log = logging.getLogger(conf.get('log_name', __name__))
        log.info(_LI('Starting Keystone auth_token middleware'))

        # NOTE(wanghong): If options are set in paste file, all the option
        # values passed into conf are string type. So, we should convert the
        # conf value into correct type.
        self._conf = _conf_values_type_convert(conf)

        # NOTE(sileht, cdent): If we don't want to use oslo.config global
        # object there are two options: set "oslo_config_project" in
        # paste.ini and the middleware will load the configuration with a
        # local oslo.config object or the caller which instantiates
        # AuthProtocol can pass in an existing oslo.config as the
        # value of the "oslo_config_config" key in conf. If both are
        # set "olso_config_config" is used.
        self._local_oslo_config = conf.get('oslo_config_config')
        if (not self._local_oslo_config) and ('oslo_config_project' in conf):
            if 'oslo_config_file' in conf:
                default_config_files = [conf['oslo_config_file']]
            else:
                default_config_files = None
            self._local_oslo_config = cfg.ConfigOpts()
            self._local_oslo_config(
                [], project=conf['oslo_config_project'],
                default_config_files=default_config_files,
                validate_default_values=True)

        if self._local_oslo_config:
            self._local_oslo_config.register_opts(_OPTS,
                                                  group=_base.AUTHTOKEN_GROUP)
            self._local_oslo_config.register_opts(_auth.OPTS,
                                                  group=_base.AUTHTOKEN_GROUP)

            loading.register_auth_conf_options(self._local_oslo_config,
                                               group=_base.AUTHTOKEN_GROUP)

        super(AuthProtocol, self).__init__(
            app,
            log=log,
            enforce_token_bind=self._conf_get('enforce_token_bind'))

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self._delay_auth_decision = self._conf_get('delay_auth_decision')
        self._include_service_catalog = self._conf_get(
            'include_service_catalog')
        self._hash_algorithms = self._conf_get('hash_algorithms')

        self._identity_server = self._create_identity_server()

        self._auth_uri = self._conf_get('auth_uri')
        if not self._auth_uri:
            self.log.warning(
                _LW('Configuring auth_uri to point to the public identity '
                    'endpoint is required; clients may not be able to '
                    'authenticate against an admin endpoint'))

            # FIXME(dolph): drop support for this fallback behavior as
            # documented in bug 1207517.

            self._auth_uri = self._identity_server.auth_uri

        self._signing_directory = _signing_dir.SigningDirectory(
            directory_name=self._conf_get('signing_dir'), log=self.log)

        self._token_cache = self._token_cache_factory()

        revocation_cache_timeout = datetime.timedelta(
            seconds=self._conf_get('revocation_cache_time'))
        self._revocations = _revocations.Revocations(revocation_cache_timeout,
                                                     self._signing_directory,
                                                     self._identity_server,
                                                     self._cms_verify,
                                                     self.log)

        self._check_revocations_for_cached = self._conf_get(
            'check_revocations_for_cached')

    def _conf_get(self, name, group=_base.AUTHTOKEN_GROUP):
        # try config from paste-deploy first
        if name in self._conf:
            return self._conf[name]
        elif self._local_oslo_config:
            return self._local_oslo_config[group][name]
        else:
            return CONF[group][name]

    def process_request(self, request):
        """Process request.

        Evaluate the headers in a request and attempt to authenticate the
        request. If authenticated then additional headers are added to the
        request for use by applications. If not authenticated the request will
        be rejected or marked unauthenticated depending on configuration.
        """
        request.remove_auth_headers()
        self._token_cache.initialize(request.environ)

        resp = super(AuthProtocol, self).process_request(request)
        if resp:
            return resp

        if not request.user_token:
            # if no user token is present then that's an invalid request
            request.user_token_valid = False

        # NOTE(jamielennox): The service status is allowed to be missing if a
        # service token is not passed. If the service status is missing that's
        # a valid request. We should find a better way to expose this from the
        # request object.
        user_status = request.user_token and request.user_token_valid
        service_status = request.headers.get('X-Service-Identity-Status',
                                             'Confirmed')

        if not (user_status and service_status == 'Confirmed'):
            if self._delay_auth_decision:
                self.log.info(_LI('Deferring reject downstream'))
            else:
                self.log.info(_LI('Rejecting request'))
                raise webob.exc.HTTPUnauthorized(
                    body='Authentication required',
                    headers=self._reject_auth_headers)

        if request.user_token_valid:
            user_auth_ref = request.token_auth._user_auth_ref
            request.set_user_headers(user_auth_ref)

            if self._include_service_catalog:
                request.set_service_catalog_headers(user_auth_ref)

        if request.service_token and request.service_token_valid:
            request.set_service_headers(request.token_auth._serv_auth_ref)

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug('Received request from %s',
                           request.token_auth._log_format)

    def process_response(self, response):
        """Process Response.

        Add ``WWW-Authenticate`` headers to requests that failed with
        ``401 Unauthenticated`` so users know where to authenticate for future
        requests.
        """
        if response.status_int == 401:
            response.headers.extend(self._reject_auth_headers)

        return response

    @property
    def _reject_auth_headers(self):
        header_val = 'Keystone uri=\'%s\'' % self._auth_uri
        return [('WWW-Authenticate', header_val)]

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

    def fetch_token(self, token):
        """Retrieve a token from either a PKI bundle or the identity server.

        :param str token: token id

        :raises exc.InvalidToken: if token is rejected
        """
        data = None
        token_hashes = None

        try:
            token_hashes = self._token_hashes(token)
            cached = self._cache_get_hashes(token_hashes)

            if cached:
                data = cached

                if self._check_revocations_for_cached:
                    # A token might have been revoked, regardless of initial
                    # mechanism used to validate it, and needs to be checked.
                    self._revocations.check(token_hashes)
            else:
                data = self._validate_offline(token, token_hashes)
                if not data:
                    data = self._identity_server.verify_token(token)

                self._token_cache.store(token_hashes[0], data)

        except (ksa_exceptions.ConnectFailure,
                ksa_exceptions.RequestTimeout,
                ksm_exceptions.RevocationListError,
                ksm_exceptions.ServiceError) as e:
            self.log.critical(_LC('Unable to validate token: %s'), e)
            raise webob.exc.HTTPServiceUnavailable()
        except ksm_exceptions.InvalidToken:
            self.log.debug('Token validation failure.', exc_info=True)
            if token_hashes:
                self._token_cache.store_invalid(token_hashes[0])
            self.log.warning(_LW('Authorization failed for token'))
            raise

        return data

    def _validate_offline(self, token, token_hashes):
        if cms.is_pkiz(token):
            token_data = _uncompress_pkiz(token)
            inform = cms.PKIZ_CMS_FORM
        elif cms.is_asn1_token(token):
            token_data = cms.token_to_cms(token)
            inform = cms.PKI_ASN1_FORM
        else:
            # Can't do offline validation for this type of token.
            return

        try:
            self._revocations.check(token_hashes)
            verified = self._cms_verify(token_data, inform)
        except ksc_exceptions.CertificateConfigError:
            self.log.warning(_LW('Fetch certificate config failed, '
                                 'fallback to online validation.'))
        except ksm_exceptions.RevocationListError:
            self.log.warning(_LW('Fetch revocation list failed, '
                                 'fallback to online validation.'))
        else:
            data = jsonutils.loads(verified)

            audit_ids = None
            if 'access' in data:
                # It's a v2 token.
                audit_ids = data['access']['token'].get('audit_ids')
            else:
                # It's a v3 token
                audit_ids = data['token'].get('audit_ids')

            if audit_ids:
                self._revocations.check_by_audit_id(audit_ids)

            return data

    def _validate_token(self, auth_ref):
        super(AuthProtocol, self)._validate_token(auth_ref)

        if auth_ref.version == 'v2.0' and not auth_ref.project_id:
            msg = _('Unable to determine service tenancy.')
            raise ksm_exceptions.InvalidToken(msg)

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
            except (ksc_exceptions.CMSError,
                    cms.subprocess.CalledProcessError) as err:
                self.log.warning(_LW('Verify error: %s'), err)
                msg = _('Token authorization failed')
                raise ksm_exceptions.InvalidToken(msg)

        try:
            return verify()
        except ksc_exceptions.CertificateConfigError:
            # the certs might be missing; unconditionally fetch to avoid racing
            self._fetch_signing_cert()
            self._fetch_ca_cert()

            try:
                # retry with certs in place
                return verify()
            except ksc_exceptions.CertificateConfigError as err:
                # if this is still occurring, something else is wrong and we
                # need err.output to identify the problem
                self.log.error(_LE('CMS Verify output: %s'), err.output)
                raise

    def _fetch_signing_cert(self):
        self._signing_directory.write_file(
            self._SIGNING_CERT_FILE_NAME,
            self._identity_server.fetch_signing_cert())

    def _fetch_ca_cert(self):
        self._signing_directory.write_file(
            self._SIGNING_CA_FILE_NAME,
            self._identity_server.fetch_ca_cert())

    def _get_auth_plugin(self):
        # NOTE(jamielennox): Ideally this would use load_from_conf_options
        # however that is not possible because we have to support the override
        # pattern we use in _conf_get. This function therefore does a manual
        # version of load_from_conf_options with the fallback plugin inline.

        group = self._conf_get('auth_section') or _base.AUTHTOKEN_GROUP

        # NOTE(jamielennox): auth_plugin was deprecated to auth_type. _conf_get
        # doesn't handle that deprecation in the case of conf dict options so
        # we have to manually check the value
        plugin_name = (self._conf_get('auth_type', group=group)
                       or self._conf.get('auth_plugin'))

        if not plugin_name:
            return _auth.AuthTokenPlugin(
                log=self.log,
                auth_admin_prefix=self._conf_get('auth_admin_prefix',
                                                 group=group),
                auth_host=self._conf_get('auth_host', group=group),
                auth_port=self._conf_get('auth_port', group=group),
                auth_protocol=self._conf_get('auth_protocol', group=group),
                identity_uri=self._conf_get('identity_uri', group=group),
                admin_token=self._conf_get('admin_token', group=group),
                admin_user=self._conf_get('admin_user', group=group),
                admin_password=self._conf_get('admin_password', group=group),
                admin_tenant_name=self._conf_get('admin_tenant_name',
                                                 group=group)
            )

        # Plugin option registration is normally done as part of the load_from
        # function rather than the register function so copy here.
        plugin_loader = loading.get_plugin_loader(plugin_name)
        plugin_opts = loading.get_auth_plugin_conf_options(plugin_loader)

        (self._local_oslo_config or CONF).register_opts(plugin_opts,
                                                        group=group)

        getter = lambda opt: self._conf_get(opt.dest, group=group)
        return plugin_loader.load_from_options_getter(getter)

    def _determine_project(self):
        """Determine a project name from all available config sources.

        The sources are checked in the following order:

          1. The paste-deploy config for auth_token middleware
          2. The keystone_authtoken in the project's config
          3. The oslo.config CONF.project property

        """
        try:
            return self._conf_get('project')
        except cfg.NoSuchOptError:
            # Prefer local oslo config object
            if self._local_oslo_config:
                return self._local_oslo_config.project
            try:
                # CONF.project will exist only if the service uses
                # oslo.config. It will only be set when the project
                # calls CONF(...) and when not set oslo.config oddly
                # raises a NoSuchOptError exception.
                return CONF.project
            except cfg.NoSuchOptError:
                return ''

    def _build_useragent_string(self):
        project = self._determine_project()
        if project:
            project_version = _get_project_version(project)
            project = '{project}/{project_version} '.format(
                project=project,
                project_version=project_version)

        ua_template = ('{project}'
                       'keystonemiddleware.auth_token/{ksm_version}')
        return ua_template.format(
            project=project,
            ksm_version=_get_project_version('keystonemiddleware'))

    def _create_identity_server(self):
        # NOTE(jamielennox): Loading Session here should be exactly the
        # same as calling Session.load_from_conf_options(CONF, GROUP)
        # however we can't do that because we have to use _conf_get to
        # support the paste.ini options.
        sess = session_loading.Session().load_from_options(
            cert=self._conf_get('certfile'),
            key=self._conf_get('keyfile'),
            cacert=self._conf_get('cafile'),
            insecure=self._conf_get('insecure'),
            timeout=self._conf_get('http_connect_timeout'),
            user_agent=self._build_useragent_string()
        )

        auth_plugin = self._get_auth_plugin()

        adap = adapter.Adapter(
            sess,
            auth=auth_plugin,
            service_type='identity',
            interface='admin',
            region_name=self._conf_get('region_name'),
            connect_retries=self._conf_get('http_request_max_retries'))

        auth_version = self._conf_get('auth_version')
        if auth_version is not None:
            auth_version = discover.normalize_version_number(auth_version)
        return _identity.IdentityServer(
            self.log,
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
            dead_retry=self._conf_get('memcache_pool_dead_retry'),
            maxsize=self._conf_get('memcache_pool_maxsize'),
            unused_timeout=self._conf_get('memcache_pool_unused_timeout'),
            conn_get_timeout=self._conf_get('memcache_pool_conn_get_timeout'),
            socket_timeout=self._conf_get('memcache_pool_socket_timeout'),
        )

        if security_strategy.lower() != 'none':
            secret_key = self._conf_get('memcache_secret_key')
            return _cache.SecureTokenCache(self.log,
                                           security_strategy,
                                           secret_key,
                                           **cache_kwargs)
        else:
            return _cache.TokenCache(self.log, **cache_kwargs)


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
InvalidToken = ksm_exceptions.InvalidToken
ServiceError = ksm_exceptions.ServiceError
ConfigurationError = ksm_exceptions.ConfigurationError
RevocationListError = ksm_exceptions.RevocationListError
