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
TOKEN-BASED AUTH MIDDLEWARE

This WSGI component:

* Verifies that incoming client requests have valid tokens by validating
  tokens with the auth service.
* Rejects unauthenticated requests UNLESS it is in 'delay_auth_decision'
  mode, which means the final decision is delegated to the downstream WSGI
  component (usually the OpenStack service)
* Collects and forwards identity information based on a valid token
  such as user name, tenant, etc

Refer to: http://docs.openstack.org/developer/python-keystoneclient/
middlewarearchitecture.html

HEADERS
-------

* Headers starting with HTTP\_ is a standard http header
* Headers starting with HTTP_X is an extended http header

Coming in from initial call from client or customer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    The client token being passed in.

HTTP_X_STORAGE_TOKEN
    The client token being passed in (legacy Rackspace use) to support
    swift/cloud files

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

WWW-Authenticate
    HTTP header returned to a user indicating which endpoint to use
    to retrieve a new token

What we add to the request for use by the OpenStack service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_IDENTITY_STATUS
    'Confirmed' or 'Invalid'
    The underlying service will only see a value of 'Invalid' if the Middleware
    is configured to run in 'delay_auth_decision' mode

HTTP_X_DOMAIN_ID
    Identity service managed unique identifier, string. Only present if
    this is a domain-scoped v3 token.

HTTP_X_DOMAIN_NAME
    Unique domain name, string. Only present if this is a domain-scoped
    v3 token.

HTTP_X_PROJECT_ID
    Identity service managed unique identifier, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_NAME
    Project name, unique within owning domain, string. Only present if
    this is a project-scoped v3 token, or a tenant-scoped v2 token.

HTTP_X_PROJECT_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    project, string.  Only present if this is a project-scoped v3 token. If
    this variable is set, this indicates that the PROJECT_NAME can only
    be assumed to be unique within this domain.

HTTP_X_PROJECT_DOMAIN_NAME
    Name of owning domain of project, string. Only present if this is a
    project-scoped v3 token. If this variable is set, this indicates that
    the PROJECT_NAME can only be assumed to be unique within this domain.

HTTP_X_USER_ID
    Identity-service managed unique identifier, string

HTTP_X_USER_NAME
    User identifier, unique within owning domain, string

HTTP_X_USER_DOMAIN_ID
    Identity service managed unique identifier of owning domain of
    user, string. If this variable is set, this indicates that the USER_NAME
    can only be assumed to be unique within this domain.

HTTP_X_USER_DOMAIN_NAME
    Name of owning domain of user, string. If this variable is set, this
    indicates that the USER_NAME can only be assumed to be unique within
    this domain.

HTTP_X_ROLES
    Comma delimited list of case-sensitive role names

HTTP_X_SERVICE_CATALOG
    json encoded keystone service catalog (optional).
    For compatibility reasons this catalog will always be in the V2 catalog
    format even if it is a v3 token.

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
    Keystone-assigned unique identifier, string. For v3 tokens, this
    will be set to the same value as HTTP_X_PROJECT_ID

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME
    User name, unique within owning domain, string

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES
    Will contain the same values as HTTP_X_ROLES.

OTHER ENVIRONMENT VARIABLES
---------------------------

keystone.token_info
    Information about the token discovered in the process of
    validation.  This may include extended information returned by the
    Keystone token validation call, as well as basic information about
    the tenant and user.

"""

import contextlib
import datetime
import logging
import os
import stat
import tempfile
import time

from keystoneclient import access
from keystoneclient.auth.identity import v2
from keystoneclient.auth import token_endpoint
from keystoneclient.common import cms
from keystoneclient import exceptions
from keystoneclient import session
import netaddr
from oslo.config import cfg
import six
from six.moves import urllib

from keystonemiddleware import _memcache_crypt as memcache_crypt
from keystonemiddleware.openstack.common import jsonutils
from keystonemiddleware.openstack.common import memorycache
from keystonemiddleware.openstack.common import timeutils


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
# to use Swift memcache instead of the local Keystone memcache. Swift memcache
# is passed in from the request environment and its identified by the
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
    cfg.StrOpt('auth_uri',
               default=None,
               # FIXME(dolph): should be default='http://127.0.0.1:5000/v2.0/',
               # or (depending on client support) an unversioned, publicly
               # accessible identity endpoint (see bug 1207517)
               help='Complete public Identity API endpoint'),
    cfg.StrOpt('identity_uri',
               default=None,
               help='Complete admin Identity API endpoint. This should '
                    'specify the unversioned root endpoint '
                    'e.g. https://localhost:35357/'),
    cfg.StrOpt('auth_version',
               default=None,
               help='API version of the admin Identity API endpoint'),
    cfg.BoolOpt('delay_auth_decision',
                default=False,
                help='Do not handle authorization requests within the'
                ' middleware, but delegate the authorization decision to'
                ' downstream WSGI components'),
    cfg.BoolOpt('http_connect_timeout',
                default=None,
                help='Request timeout value for communicating with Identity'
                ' API server.'),
    cfg.IntOpt('http_request_max_retries',
               default=3,
               help='How many times are we trying to reconnect when'
               ' communicating with Identity API Server.'),
    cfg.StrOpt('admin_token',
               secret=True,
               help='This option is deprecated and may be removed in a future'
               ' release. Single shared secret with the Keystone configuration'
               ' used for bootstrapping a Keystone installation, or otherwise'
               ' bypassing the normal authentication process. This option'
               ' should not be used, use `admin_user` and `admin_password`'
               ' instead.'),
    cfg.StrOpt('admin_user',
               help='Keystone account username'),
    cfg.StrOpt('admin_password',
               secret=True,
               help='Keystone account password'),
    cfg.StrOpt('admin_tenant_name',
               default='admin',
               help='Keystone service account tenant name to validate'
               ' user tokens'),
    cfg.StrOpt('cache',
               default=None,
               help='Env key for the swift cache'),
    cfg.StrOpt('certfile',
               help='Required if Keystone server requires client certificate'),
    cfg.StrOpt('keyfile',
               help='Required if Keystone server requires client certificate'),
    cfg.StrOpt('cafile', default=None,
               help='A PEM encoded Certificate Authority to use when '
                    'verifying HTTPs connections. Defaults to system CAs.'),
    cfg.BoolOpt('insecure', default=False, help='Verify HTTPS connections.'),
    cfg.StrOpt('signing_dir',
               help='Directory used to cache files related to PKI tokens'),
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
               help='(optional) if defined, indicate whether token data'
               ' should be authenticated or authenticated and encrypted.'
               ' Acceptable values are MAC or ENCRYPT.  If MAC, token data is'
               ' authenticated (with HMAC) in the cache. If ENCRYPT, token'
               ' data is encrypted and authenticated in the cache. If the'
               ' value is not one of these options or empty, auth_token will'
               ' raise an exception on initialization.'),
    cfg.StrOpt('memcache_secret_key',
               default=None,
               secret=True,
               help='(optional, mandatory if memcache_security_strategy is'
               ' defined) this string is used for key derivation.'),
    cfg.BoolOpt('include_service_catalog',
                default=True,
                help='(optional) indicate whether to set the X-Service-Catalog'
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
                ' Keystone server.'),
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
CONF.register_opts(_OPTS, group='keystone_authtoken')

_LIST_OF_VERSIONS_TO_ATTEMPT = ['v3.0', 'v2.0']


class _BIND_MODE:
    DISABLED = 'disabled'
    PERMISSIVE = 'permissive'
    STRICT = 'strict'
    REQUIRED = 'required'
    KERBEROS = 'kerberos'


def _will_expire_soon(expiry):
    """Determines if expiration is about to occur.

    :param expiry: a datetime of the expected expiration
    :returns: boolean : true if expiration is within 30 seconds
    """
    soon = (timeutils.utcnow() + datetime.timedelta(seconds=30))
    return expiry < soon


def _token_is_v2(token_info):
    return ('access' in token_info)


def _token_is_v3(token_info):
    return ('token' in token_info)


def _confirm_token_not_expired(data):
    if not data:
        raise InvalidUserToken('Token authorization failed')
    if _token_is_v2(data):
        timestamp = data['access']['token']['expires']
    elif _token_is_v3(data):
        timestamp = data['token']['expires_at']
    else:
        raise InvalidUserToken('Token authorization failed')
    expires = timeutils.parse_isotime(timestamp)
    expires = timeutils.normalize_time(expires)
    utcnow = timeutils.utcnow()
    if utcnow >= expires:
        raise InvalidUserToken('Token authorization failed')
    return timeutils.isotime(at=expires, subsecond=True)


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


class InvalidUserToken(Exception):
    pass


class ServiceError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class NetworkError(Exception):
    pass


class _MiniResp(object):
    def __init__(self, error_message, env, headers=[]):
        # The HEAD method is unique: it must never return a body, even if
        # it reports an error (RFC-2616 clause 9.4). We relieve callers
        # from varying the error responses depending on the method.
        if env['REQUEST_METHOD'] == 'HEAD':
            self.body = ['']
        else:
            self.body = [error_message]
        self.headers = list(headers)
        self.headers.append(('Content-type', 'text/plain'))


class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls."""

    def __init__(self, app, conf):
        self._LOG = logging.getLogger(conf.get('log_name', __name__))
        self._LOG.info('Starting keystone auth_token middleware')
        self._conf = conf
        self._app = app

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self._delay_auth_decision = (self._conf_get('delay_auth_decision') in
                                     (True, 'true', 't', '1', 'on', 'yes', 'y')
                                     )

        self._identity_uri = self._conf_get('identity_uri')

        # NOTE(jamielennox): it does appear here that our default arguments
        # are backwards. We need to do it this way so that we can handle the
        # same deprecation strategy for CONF and the conf variable.
        if not self._identity_uri:
            self._LOG.warning('Configuring admin URI using auth fragments. '
                              'This is deprecated, use \'identity_uri\''
                              ' instead.')

            auth_host = self._conf_get('auth_host')
            auth_port = int(self._conf_get('auth_port'))
            auth_protocol = self._conf_get('auth_protocol')
            auth_admin_prefix = self._conf_get('auth_admin_prefix')

            if netaddr.valid_ipv6(auth_host):
                # Note(dzyu) it is an IPv6 address, so it needs to be wrapped
                # with '[]' to generate a valid IPv6 URL, based on
                # http://www.ietf.org/rfc/rfc2732.txt
                auth_host = '[%s]' % auth_host

            self._identity_uri = '%s://%s:%s' % (auth_protocol,
                                                 auth_host,
                                                 auth_port)

            if auth_admin_prefix:
                self._identity_uri = '%s/%s' % (self._identity_uri,
                                                auth_admin_prefix.strip('/'))

        else:
            self._identity_uri = self._identity_uri.rstrip('/')

        self._session = self._session_factory()

        self._http_request_max_retries = self._conf_get(
            'http_request_max_retries')

        self._include_service_catalog = self._conf_get(
            'include_service_catalog')

        self._identity_server = self._identity_server_factory()

        # signing
        self._signing_dirname = self._conf_get('signing_dir')
        if self._signing_dirname is None:
            self._signing_dirname = tempfile.mkdtemp(
                prefix='keystone-signing-')
        self._LOG.info('Using %s as cache directory for signing certificate',
                       self._signing_dirname)
        self._verify_signing_dir()

        val = '%s/signing_cert.pem' % self._signing_dirname
        self._signing_cert_file_name = val
        val = '%s/cacert.pem' % self._signing_dirname
        self._signing_ca_file_name = val
        val = '%s/revoked.pem' % self._signing_dirname
        self._revoked_file_name = val

        self._memcache_security_strategy = (
            self._conf_get('memcache_security_strategy'))
        self._token_cache = self._token_cache_factory()
        self._token_revocation_list_prop = None
        self._token_revocation_list_fetched_time_prop = None
        self._token_revocation_list_cache_timeout = datetime.timedelta(
            seconds=self._conf_get('revocation_cache_time'))

        self._check_revocations_for_cached = self._conf_get(
            'check_revocations_for_cached')

    def _conf_get(self, name):
        # try config from paste-deploy first
        if name in self._conf:
            return self._conf[name]
        else:
            return CONF.keystone_authtoken[name]

    def __call__(self, env, start_response):
        """Handle incoming request.

        Authenticate send downstream on success. Reject request if
        we can't authenticate.

        """
        self._LOG.debug('Authenticating user token')

        self._token_cache.initialize(env)

        try:
            self._remove_auth_headers(env)
            user_token = self._get_user_token_from_header(env)
            token_info = self._validate_user_token(user_token, env)
            env['keystone.token_info'] = token_info
            user_headers = self._build_user_headers(token_info)
            self._add_headers(env, user_headers)
            return self._app(env, start_response)

        except InvalidUserToken:
            if self._delay_auth_decision:
                self._LOG.info(
                    'Invalid user token - deferring reject downstream')
                self._add_headers(env, {'X-Identity-Status': 'Invalid'})
                return self._app(env, start_response)
            else:
                self._LOG.info('Invalid user token - rejecting request')
                return self._reject_request(env, start_response)

        except ServiceError as e:
            self._LOG.critical('Unable to obtain admin token: %s', e)
            resp = _MiniResp('Service unavailable', env)
            start_response('503 Service Unavailable', resp.headers)
            return resp.body

    def _remove_auth_headers(self, env):
        """Remove headers so a user can't fake authentication.

        :param env: wsgi request environment

        """
        auth_headers = (
            'X-Identity-Status',
            'X-Domain-Id',
            'X-Domain-Name',
            'X-Project-Id',
            'X-Project-Name',
            'X-Project-Domain-Id',
            'X-Project-Domain-Name',
            'X-User-Id',
            'X-User-Name',
            'X-User-Domain-Id',
            'X-User-Domain-Name',
            'X-Roles',
            'X-Service-Catalog',
            # Deprecated
            'X-User',
            'X-Tenant-Id',
            'X-Tenant-Name',
            'X-Tenant',
            'X-Role',
        )
        self._LOG.debug('Removing headers from request environment: %s',
                        ','.join(auth_headers))
        self._remove_headers(env, auth_headers)

    def _get_user_token_from_header(self, env):
        """Get token id from request.

        :param env: wsgi request environment
        :return token id
        :raises InvalidUserToken if no token is provided in request

        """
        token = self._get_header(env, 'X-Auth-Token',
                                 self._get_header(env, 'X-Storage-Token'))
        if token:
            return token
        else:
            if not self._delay_auth_decision:
                self._LOG.warn('Unable to find authentication token'
                               ' in headers')
                self._LOG.debug('Headers: %s', env)
            raise InvalidUserToken('Unable to find token in headers')

    def _reject_request(self, env, start_response):
        """Redirect client to auth server.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns HTTPUnauthorized http response

        """
        header_val = 'Keystone uri=\'%s\'' % self._identity_server.auth_uri
        headers = [('WWW-Authenticate', header_val)]
        resp = _MiniResp('Authentication required', env, headers)
        start_response('401 Unauthorized', resp.headers)
        return resp.body

    def _validate_user_token(self, user_token, env, retry=True):
        """Authenticate user token

        :param user_token: user's token id
        :param retry: Ignored, as it is not longer relevant
        :return uncrypted body of the token if the token is valid
        :raise InvalidUserToken if token is rejected
        :no longer raises ServiceError since it no longer makes RPC

        """
        token_id = None

        try:
            token_ids, cached = self._token_cache.get(user_token)
            token_id = token_ids[0]
            if cached:
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
                            raise InvalidUserToken(
                                'Token authorization failed')
            elif cms.is_pkiz(user_token):
                verified = self._verify_pkiz_token(user_token, token_ids)
                data = jsonutils.loads(verified)
            elif cms.is_asn1_token(user_token):
                verified = self._verify_signed_token(user_token, token_ids)
                data = jsonutils.loads(verified)
            else:
                data = self._identity_server.verify_token(user_token, retry)
            expires = _confirm_token_not_expired(data)
            self._confirm_token_bind(data, env)
            self._token_cache.store(token_id, data, expires)
            return data
        except NetworkError:
            self._LOG.debug('Token validation failure.', exc_info=True)
            self._LOG.warn('Authorization failed for token')
            raise InvalidUserToken('Token authorization failed')
        except Exception:
            self._LOG.debug('Token validation failure.', exc_info=True)
            if token_id:
                self._token_cache.store_invalid(token_id)
            self._LOG.warn('Authorization failed for token')
            raise InvalidUserToken('Token authorization failed')

    def _build_user_headers(self, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user - see main
        doc info at start of file for details of headers to be defined.

        :param token_info: token object returned by keystone on authentication
        :raise InvalidUserToken when unable to parse token object

        """
        auth_ref = access.AccessInfo.factory(body=token_info)
        roles = ','.join(auth_ref.role_names)

        if _token_is_v2(token_info) and not auth_ref.project_id:
            raise InvalidUserToken('Unable to determine tenancy.')

        rval = {
            'X-Identity-Status': 'Confirmed',
            'X-Domain-Id': auth_ref.domain_id,
            'X-Domain-Name': auth_ref.domain_name,
            'X-Project-Id': auth_ref.project_id,
            'X-Project-Name': auth_ref.project_name,
            'X-Project-Domain-Id': auth_ref.project_domain_id,
            'X-Project-Domain-Name': auth_ref.project_domain_name,
            'X-User-Id': auth_ref.user_id,
            'X-User-Name': auth_ref.username,
            'X-User-Domain-Id': auth_ref.user_domain_id,
            'X-User-Domain-Name': auth_ref.user_domain_name,
            'X-Roles': roles,
            # Deprecated
            'X-User': auth_ref.username,
            'X-Tenant-Id': auth_ref.project_id,
            'X-Tenant-Name': auth_ref.project_name,
            'X-Tenant': auth_ref.project_name,
            'X-Role': roles,
        }

        self._LOG.debug('Received request from user: %s with project_id : %s'
                        ' and roles: %s ',
                        auth_ref.user_id, auth_ref.project_id, roles)

        if self._include_service_catalog and auth_ref.has_service_catalog():
            catalog = auth_ref.service_catalog.get_data()
            if _token_is_v3(token_info):
                catalog = _v3_to_v2_catalog(catalog)
            rval['X-Service-Catalog'] = jsonutils.dumps(catalog)

        return rval

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

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
            msg = 'Token authorization failed'

        raise InvalidUserToken(msg)

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
                self._LOG.info('No bind information present in token.')
                self._invalid_user_token()

        # get the named mode if bind_mode is not one of the predefined
        if permissive or bind_mode == _BIND_MODE.REQUIRED:
            name = None
        else:
            name = bind_mode

        if name and name not in bind:
            self._LOG.info('Named bind mode %s not in bind information', name)
            self._invalid_user_token()

        for bind_type, identifier in six.iteritems(bind):
            if bind_type == _BIND_MODE.KERBEROS:
                if not env.get('AUTH_TYPE', '').lower() == 'negotiate':
                    self._LOG.info('Kerberos credentials required and '
                                   'not present.')
                    self._invalid_user_token()

                if not env.get('REMOTE_USER') == identifier:
                    self._LOG.info('Kerberos credentials do not match '
                                   'those in bind.')
                    self._invalid_user_token()

                self._LOG.debug('Kerberos bind authentication successful.')

            elif bind_mode == _BIND_MODE.PERMISSIVE:
                self._LOG.debug('Ignoring Unknown bind for permissive mode: '
                                '%(bind_type)s: %(identifier)s.',
                                {'bind_type': bind_type,
                                 'identifier': identifier})

            else:
                self._LOG.info('Couldn`t verify unknown bind: %(bind_type)s: '
                               '%(identifier)s.',
                               {'bind_type': bind_type,
                                'identifier': identifier})
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
                self._LOG.warning('Verify error: %s', err)
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
                self._LOG.error('CMS Verify output: %s', err.output)
                raise

    def _verify_signed_token(self, signed_text, token_ids):
        """Check that the token is unrevoked and has a valid signature."""
        if self._is_signed_token_revoked(token_ids):
            raise InvalidUserToken('Token has been revoked')

        formatted = cms.token_to_cms(signed_text)
        verified = self._cms_verify(formatted)
        return verified

    def _verify_pkiz_token(self, signed_text, token_ids):
        if self._is_signed_token_revoked(token_ids):
            raise InvalidUserToken('Token has been revoked')
        try:
            uncompressed = cms.pkiz_uncompress(signed_text)
            verified = self._cms_verify(uncompressed, inform=cms.PKIZ_CMS_FORM)
            return verified
        # TypeError If the signed_text is not zlib compressed
        except TypeError:
            raise InvalidUserToken(signed_text)

    def _verify_signing_dir(self):
        if os.path.exists(self._signing_dirname):
            if not os.access(self._signing_dirname, os.W_OK):
                raise ConfigurationError(
                    'unable to access signing_dir %s' % self._signing_dirname)
            uid = os.getuid()
            if os.stat(self._signing_dirname).st_uid != uid:
                self._LOG.warning('signing_dir is not owned by %s', uid)
            current_mode = stat.S_IMODE(os.stat(self._signing_dirname).st_mode)
            if current_mode != stat.S_IRWXU:
                self._LOG.warning(
                    'signing_dir mode is %s instead of %s',
                    oct(current_mode), oct(stat.S_IRWXU))
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

    # NOTE(hrybacki): This and subsequent factory functions are part of a
    # cleanup and better organization effort of AuthProtocol.
    def _session_factory(self):
        sess = session.Session.construct(dict(
            cert=self._conf_get('certfile'),
            key=self._conf_get('keyfile'),
            cacert=self._conf_get('cafile'),
            insecure=self._conf_get('insecure'),
            timeout=self._conf_get('http_connect_timeout')
        ))
        # FIXME(jamielennox): Yes. This is wrong. We should be determining the
        # plugin to use based on a combination of discovery and inputs. Much
        # of this can be changed when we get keystoneclient 0.10. For now this
        # hardcoded path is EXACTLY the same as the original auth_token did.
        auth_url = '%s/v2.0' % self._identity_uri

        admin_token = self._conf_get('admin_token')
        if admin_token:
            self._LOG.warning(
                "The admin_token option in the auth_token middleware is "
                "deprecated and should not be used. The admin_user and "
                "admin_password options should be used instead. The "
                "admin_token option may be removed in a future release.")
            sess.auth = token_endpoint.Token(auth_url, admin_token)
        else:
            sess.auth = v2.Password(
                auth_url,
                username=self._conf_get('admin_user'),
                password=self._conf_get('admin_password'),
                tenant_name=self._conf_get('admin_tenant_name'))
        return sess

    def _identity_server_factory(self):
        identity_server = _IdentityServer(
            self._LOG,
            self._session,
            include_service_catalog=self._include_service_catalog,
            identity_uri=self._identity_uri,
            auth_uri=self._conf_get('auth_uri'),
            http_request_max_retries=self._http_request_max_retries,
            auth_version=self._conf_get('auth_version'))
        return identity_server

    def _token_cache_factory(self):
        token_cache = _TokenCache(
            self._LOG,
            cache_time=int(self._conf_get('token_cache_time')),
            hash_algorithms=self._conf_get('hash_algorithms'),
            env_cache_name=self._conf_get('cache'),
            memcached_servers=self._conf_get('memcached_servers'),
            memcache_security_strategy=self._memcache_security_strategy,
            memcache_secret_key=self._conf_get('memcache_secret_key'))
        return token_cache


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


class _IdentityServer(object):
    """Operations on the Identity API server.

    The auth_token middleware needs to communicate with the Identity API server
    to validate UUID tokens, fetch the revocation list, signing certificates,
    etc. This class encapsulates the data and methods to perform these
    operations.

    """
    def __init__(self, log, session, include_service_catalog=None,
                 identity_uri=None, auth_uri=None,
                 http_request_max_retries=None, auth_version=None):
        self._LOG = log
        self._include_service_catalog = include_service_catalog
        self._req_auth_version = auth_version

        # where to find the auth service (we use this to validate tokens)
        self._identity_uri = identity_uri
        self.auth_uri = auth_uri

        self._session = session

        if self.auth_uri is None:
            self._LOG.warning(
                'Configuring auth_uri to point to the public identity '
                'endpoint is required; clients may not be able to '
                'authenticate against an admin endpoint')

            # FIXME(dolph): drop support for this fallback behavior as
            # documented in bug 1207517.
            # NOTE(jamielennox): we urljoin '/' to get just the base URI as
            # this is the original behaviour.
            self.auth_uri = urllib.parse.urljoin(self._identity_uri, '/')
            self.auth_uri = self.auth_uri.rstrip('/')

        self._auth_version = None
        self._http_request_max_retries = http_request_max_retries

    def verify_token(self, user_token, retry=True):
        """Authenticate user token with keystone.

        :param user_token: user's token id
        :param retry: flag that forces the middleware to retry
                      user authentication when an indeterminate
                      response is received. Optional.
        :return: token object received from keystone on success
        :raise InvalidUserToken: if token is rejected
        :raise ServiceError: if unable to authenticate token

        """
        user_token = _safe_quote(user_token)

        # Determine the highest api version we can use.
        if not self._auth_version:
            self._auth_version = self._choose_api_version()

        if self._auth_version == 'v3.0':
            headers = {'X-Subject-Token': user_token}
            path = '/v3/auth/tokens'
            if not self._include_service_catalog:
                # NOTE(gyee): only v3 API support this option
                path = path + '?nocatalog'

        else:
            headers = {}
            path = '/v2.0/tokens/%s' % user_token

        try:
            response, data = self._json_request(
                'GET',
                path,
                authenticated=True,
                headers=headers)
        except exceptions.NotFound as e:
            self._LOG.warn('Authorization failed for token')
            self._LOG.warn('Identity response: %s' % e.response.text)
        except exceptions.Unauthorized as e:
            self._LOG.info('Keystone rejected authorization')
            self._LOG.warn('Identity response: %s' % e.response.text)
            if retry:
                self._LOG.info('Retrying validation')
                return self.verify_token(user_token, False)
        except exceptions.HttpError as e:
            self._LOG.error('Bad response code while validating token: %s',
                            e.http_status)
            self._LOG.warn('Identity response: %s' % e.response.text)
        else:
            if response.status_code == 200:
                return data

            raise InvalidUserToken()

    def fetch_revocation_list(self):
        try:
            response, data = self._json_request('GET', '/v2.0/tokens/revoked',
                                                authenticated=True)
        except exceptions.HTTPError as e:
            raise ServiceError('Failed to fetch token revocation list: %d' %
                               e.http_status)
        if response.status_code != 200:
            raise ServiceError('Unable to fetch token revocation list.')
        if 'signed' not in data:
            raise ServiceError('Revocation list improperly formatted.')
        return data['signed']

    def fetch_signing_cert(self):
        return self._fetch_cert_file('signing')

    def fetch_ca_cert(self):
        return self._fetch_cert_file('ca')

    def _choose_api_version(self):
        """Determine the api version that we should use."""

        # If the configuration specifies an auth_version we will just
        # assume that is correct and use it.  We could, of course, check
        # that this version is supported by the server, but in case
        # there are some problems in the field, we want as little code
        # as possible in the way of letting auth_token talk to the
        # server.
        if self._req_auth_version:
            version_to_use = self._req_auth_version
            self._LOG.info('Auth Token proceeding with requested %s apis',
                           version_to_use)
        else:
            version_to_use = None
            versions_supported_by_server = self._get_supported_versions()
            if versions_supported_by_server:
                for version in _LIST_OF_VERSIONS_TO_ATTEMPT:
                    if version in versions_supported_by_server:
                        version_to_use = version
                        break
            if version_to_use:
                self._LOG.info('Auth Token confirmed use of %s apis',
                               version_to_use)
            else:
                self._LOG.error(
                    'Attempted versions [%s] not in list supported by '
                    'server [%s]',
                    ', '.join(_LIST_OF_VERSIONS_TO_ATTEMPT),
                    ', '.join(versions_supported_by_server))
                raise ServiceError('No compatible apis supported by server')
        return version_to_use

    def _get_supported_versions(self):
        versions = []
        response, data = self._json_request('GET', '/', authenticated=False)
        if response.status_code == 501:
            self._LOG.warning(
                'Old keystone installation found...assuming v2.0')
            versions.append('v2.0')
        elif response.status_code != 300:
            self._LOG.error('Unable to get version info from keystone: %s',
                            response.status_code)
            raise ServiceError('Unable to get version info from keystone')
        else:
            try:
                for version in data['versions']['values']:
                    versions.append(version['id'])
            except KeyError:
                self._LOG.error(
                    'Invalid version response format from server')
                raise ServiceError('Unable to parse version response '
                                   'from keystone')

        self._LOG.debug('Server reports support for api versions: %s',
                        ', '.join(versions))
        return versions

    def _http_request(self, method, path, **kwargs):
        """HTTP request helper used to make unspecified content type requests.

        :param method: http method
        :param path: relative request url
        :return (http response object, response body)
        :raise ServerError when unable to communicate with keystone

        """
        url = '%s/%s' % (self._identity_uri, path.lstrip('/'))

        RETRIES = self._http_request_max_retries
        retry = 0
        while True:
            try:
                response = self._session.request(url, method, **kwargs)
                break
            except exceptions.HTTPError:
                # NOTE(hrybacki): unlike the requests library that return
                # response object with a status code e.g. 400, http failures
                # in session take these responses and create HTTPError
                # exceptions to be handled at a higher level.
                raise
            except Exception as e:
                if retry >= RETRIES:
                    self._LOG.error('HTTP connection exception: %s', e)
                    raise NetworkError('Unable to communicate with keystone')
                # NOTE(vish): sleep 0.5, 1, 2
                self._LOG.warn('Retrying on HTTP connection exception: %s', e)
                time.sleep(2.0 ** retry / 2)
                retry += 1

        return response

    def _json_request(self, method, path, **kwargs):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param **kwargs: additional parameters used by session or endpoint
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone

        """
        headers = kwargs.setdefault('headers', {})
        headers['Accept'] = 'application/json'

        response = self._http_request(method, path, **kwargs)

        try:
            data = jsonutils.loads(response.text)
        except ValueError:
            self._LOG.debug('Keystone did not return json-encoded body')
            data = {}

        return response, data

    def _fetch_cert_file(self, cert_type):
        if not self._auth_version:
            self._auth_version = self._choose_api_version()

        if self._auth_version == 'v3.0':
            if cert_type == 'signing':
                cert_type = 'certificates'
            path = '/v3/OS-SIMPLE-CERT/' + cert_type
        else:
            path = '/v2.0/certificates/' + cert_type
        try:
            response = self._http_request('GET', path, authenticated=False)
        except exceptions.HTTPError as e:
            raise exceptions.CertificateConfigError(e.details)
        if response.status_code != 200:
            raise exceptions.CertificateConfigError(response.text)
        return response.text


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
                 memcache_security_strategy=None, memcache_secret_key=None):
        self._LOG = log
        self._cache_time = cache_time
        self._hash_algorithms = hash_algorithms
        self._env_cache_name = env_cache_name
        self._memcached_servers = memcached_servers

        # memcache value treatment, ENCRYPT or MAC
        self._memcache_security_strategy = memcache_security_strategy
        if self._memcache_security_strategy is not None:
            self._memcache_security_strategy = (
                self._memcache_security_strategy.upper())
        self._memcache_secret_key = memcache_secret_key

        self._cache_pool = None
        self._initialized = False

        self._assert_valid_memcache_protection_config()

    def initialize(self, env):
        if self._initialized:
            return

        self._cache_pool = _CachePool(env.get(self._env_cache_name),
                                      self._memcached_servers)
        self._initialized = True

    def get(self, user_token):
        """Check if the token is cached already.

        Returns a tuple. The first element is a list of token IDs, where the
        first one is the preferred hash.

        The second element is the token data from the cache if the token was
        cached, otherwise ``None``.

        :raises InvalidUserToken: if the token is invalid

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

    def _assert_valid_memcache_protection_config(self):
        if self._memcache_security_strategy:
            if self._memcache_security_strategy not in ('MAC', 'ENCRYPT'):
                raise ConfigurationError('memcache_security_strategy must be '
                                         'ENCRYPT or MAC')
            if not self._memcache_secret_key:
                raise ConfigurationError('memcache_secret_key must be defined '
                                         'when a memcache_security_strategy '
                                         'is defined')

    def _cache_get(self, token_id):
        """Return token information from cache.

        If token is invalid raise InvalidUserToken
        return token only if fresh (not expired).
        """

        if not token_id:
            # Nothing to do
            return

        if self._memcache_security_strategy is None:
            key = self._CACHE_KEY_TEMPLATE % token_id
            with self._cache_pool.reserve() as cache:
                serialized = cache.get(key)
        else:
            secret_key = self._memcache_secret_key
            if isinstance(secret_key, six.string_types):
                secret_key = secret_key.encode('utf-8')
            security_strategy = self._memcache_security_strategy
            if isinstance(security_strategy, six.string_types):
                security_strategy = security_strategy.encode('utf-8')
            keys = memcache_crypt.derive_keys(
                token_id,
                secret_key,
                security_strategy)
            cache_key = self._CACHE_KEY_TEMPLATE % (
                memcache_crypt.get_cache_key(keys))
            with self._cache_pool.reserve() as cache:
                raw_cached = cache.get(cache_key)
            try:
                # unprotect_data will return None if raw_cached is None
                serialized = memcache_crypt.unprotect_data(keys,
                                                           raw_cached)
            except Exception:
                msg = 'Failed to decrypt/verify cache data'
                self._LOG.exception(msg)
                # this should have the same effect as data not
                # found in cache
                serialized = None

        if serialized is None:
            return None

        # Note that _INVALID_INDICATOR and (data, expires) are the only
        # valid types of serialized cache entries, so there is not
        # a collision with jsonutils.loads(serialized) == None.
        if not isinstance(serialized, six.string_types):
            serialized = serialized.decode('utf-8')
        cached = jsonutils.loads(serialized)
        if cached == self._INVALID_INDICATOR:
            self._LOG.debug('Cached Token is marked unauthorized')
            raise InvalidUserToken('Token authorization failed')

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
            raise InvalidUserToken('Token authorization failed')

    def _cache_store(self, token_id, data):
        """Store value into memcache.

        data may be _INVALID_INDICATOR or a tuple like (data, expires)

        """
        serialized_data = jsonutils.dumps(data)
        if isinstance(serialized_data, six.text_type):
            serialized_data = serialized_data.encode('utf-8')
        if self._memcache_security_strategy is None:
            cache_key = self._CACHE_KEY_TEMPLATE % token_id
            data_to_store = serialized_data
        else:
            secret_key = self._memcache_secret_key
            if isinstance(secret_key, six.string_types):
                secret_key = secret_key.encode('utf-8')
            security_strategy = self._memcache_security_strategy
            if isinstance(security_strategy, six.string_types):
                security_strategy = security_strategy.encode('utf-8')
            keys = memcache_crypt.derive_keys(
                token_id, secret_key, security_strategy)
            cache_key = memcache_crypt.get_cache_key(keys)
            cache_key = self._CACHE_KEY_TEMPLATE % cache_key
            data_to_store = memcache_crypt.protect_data(keys, serialized_data)

        with self._cache_pool.reserve() as cache:
            cache.set(cache_key, data_to_store, time=self._cache_time)


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
    """Run this module directly to start a protected echo service::

        $ python -m keystonemiddleware.auth_token

    When the ``auth_token`` module authenticates a request, the echo service
    will respond with all the environment variables presented to it by this
    module.

    """
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
