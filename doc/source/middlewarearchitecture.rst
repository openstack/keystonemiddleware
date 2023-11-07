..
      Copyright 2011-2013 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

=======================
Middleware Architecture
=======================

Abstract
========

The keystonemiddleware architecture supports a common authentication protocol
in use between the OpenStack projects. By using keystone as a common
authentication and authorization mechanism, various OpenStack projects can
leverage the existing authentication and authorization systems in use.

In this document, we describe the architecture and responsibilities of the
authentication middleware which acts as the internal API mechanism for
OpenStack projects based on the WSGI standard.

This documentation describes the implementation in
:class:`keystonemiddleware.auth_token`

Specification Overview
======================

'Authentication' is the process of determining that users are who they say they
are. Typically, 'authentication protocols' such as HTTP Basic Auth, Digest
Access, public key, token, etc, are used to verify a user's identity. In this
document, we define an 'authentication component' as a software module that
implements an authentication protocol for an OpenStack service. Bearer tokens
are currently the most common authentication protocol used within OpenStack.

At a high level, an authentication middleware component is a proxy that
intercepts HTTP calls from clients and populates HTTP headers in the request
context for other WSGI middleware or applications to use. The general flow
of the middleware processing is:

* clear any existing authorization headers to prevent forgery
* collect the token from the existing HTTP request headers
* validate the token

  * if valid, populate additional headers representing the identity that has
    been authenticated and authorized
  * if invalid, or no token present, reject the request (HTTPUnauthorized)
    or pass along a header indicating the request is unauthorized (configurable
    in the middleware)
  * if the keystone service is unavailable to validate the token, reject
    the request with HTTPServiceUnavailable.

.. _authComponent:

Authentication Component
------------------------

The following shows the default behavior of an Authentication Component
deployed in front of an OpenStack service.

.. image:: images/graphs_authComp.svg
   :width: 100%
   :height: 180
   :alt: An Authentication Component


The Authentication Component, or middleware, will reject any unauthenticated
requests, only allowing authenticated requests through to the OpenStack
service.

.. _authComponentDelegated:

Authentication Component (Delegated Mode)
-----------------------------------------

The Authentication Component may be configured to operate in a 'delegated
mode'. In this mode, the decision to reject or accept an unauthenticated client
is delegated to the OpenStack service.

Here, requests are forwarded to the OpenStack service with an identity status
message that indicates whether the identity of the client has been confirmed or
is indeterminate. The consuming OpenStack service decides whether or not a
rejection message should be sent to the client.

.. image:: images/graphs_authCompDelegate.svg
   :width: 100%
   :height: 180
   :alt: An Authentication Component (Delegated Mode)

.. _deployStrategies:

Deployment Strategy
===================

The middleware is intended to be used inline with OpenStack WSGI components,
based on the Oslo WSGI middleware class. It is typically deployed
as a configuration element in a paste configuration pipeline of other
middleware components, with the pipeline terminating in the service
application. The middleware conforms to the python WSGI standard [PEP-333]_.
In initializing the middleware, a configuration item (which acts like a python
dictionary) is passed to the middleware with relevant configuration options.

Configuration
-------------

The middleware is configured within the config file of the main application as
a WSGI component. Example for the auth_token middleware:

.. code-block:: ini

    [app:myService]
    paste.app_factory = myService:app_factory

    [pipeline:main]
    pipeline = authtoken myService

    [filter:authtoken]
    paste.filter_factory = keystonemiddleware.auth_token:filter_factory

.. literalinclude:: _static/keystonemiddleware.conf.sample

If the ``auth_type`` configuration option is set, you may need to refer to
the `Authentication Plugins <https://docs.openstack.org/keystoneauth/latest/
authentication-plugins.html>`_ document for how to configure the auth_token
middleware.

For services which have a separate paste-deploy ini file, auth_token middleware
can be alternatively configured in [keystone_authtoken] section in the main
config file. For example in nova, all middleware parameters can be removed
from ``api-paste.ini``:

.. code-block:: ini

    [filter:authtoken]
    paste.filter_factory = keystonemiddleware.auth_token:filter_factory

and set in ``nova.conf``:

.. code-block:: ini

    [DEFAULT]
    auth_strategy=keystone

    [keystone_authtoken]
    identity_uri = http://127.0.0.1:5000
    admin_user = admin
    admin_password = SuperSekretPassword
    admin_tenant_name = service
    # Any of the options that could be set in api-paste.ini can be set here.

.. NOTE::
    Middleware parameters in paste config take priority and must be removed
    to use options in the [keystone_authtoken] section.

The following is an example of a service's auth_token middleware configuration
when ``auth_type`` is set to ``password``.

.. code-block:: ini

    [keystone_authtoken]
    auth_type = password
    project_domain_name = Default
    project_name = service
    user_domain_name = Default
    username = nova
    password = ServicePassword
    interface = public
    auth_url = http://127.0.0.1:5000
    # Any of the options that could be set in api-paste.ini can be set here.

If using an ``auth_type``, connection to the Identity service will be
established on the ``interface`` as registered in the service catalog.
In the case where you are using an ``auth_type`` and have multiple regions,
also specify the ``region_name`` option to fetch the correct endpoint.

If the service doesn't use the global oslo.config object (CONF), then the
oslo config project name can be set it in paste config and
keystonemiddleware will load the project configuration itself.
Optionally the location of the configuration file can be set if oslo.config
is not able to discover it.

.. code-block:: ini

    [filter:authtoken]
    paste.filter_factory = keystonemiddleware.auth_token:filter_factory
    oslo_config_project = nova
    # oslo_config_file = /not_discoverable_location/nova.conf

Configuration for external authorization
----------------------------------------

If an external authorization server is used from Keystonemiddleware, the
configuration file settings for the main application must be changed. The
system supports 5 authentication methods, tls_client_auth, client_secret_basic,
client_secret_post, client_secret_jwt, and private_key_jwt, which are specified
in auth_method. The required config depends on the authentication method.
The two config file modifications required when using an external authorization
server are described below.

.. NOTE::
    Settings for accepting https requests and mTLS connections depend on each
    OpenStack service that uses Keystonemiddleware.

Change to use the ext_oauth2_token filter instead of authtoken:

.. code-block:: ini

    [pipeline:main]
    pipeline = ext_oauth2_token myService

    [filter:ext_oauth2_token]
    paste.filter_factory = keystonemiddleware.external_oauth2_token:filter_factory

Add the config group for external authentication server:

.. code-block:: ini

    [ext_oauth2_auth]
    # Required if identity server requires client certificate.
    #certfile = <None>

    # Required if identity server requires client private key.
    #keyfile = <None>

    # A PEM encoded Certificate Authority to use when verifying HTTPs
    # connections. Defaults to system CAs.
    #cafile = <None>

    # Verify HTTPS connections.
    #insecure = False

    # Request timeout value for communicating with Identity API server.
    #http_connect_timeout = <None>

    # The endpoint for introspect API, it is used to verify that the OAuth 2.0
    # access token is valid.
    #introspect_endpoint = <None>

    # The Audience should be the URL of the Authorization Server's Token
    # Endpoint. The Authorization Server will verify that it is an intended
    # audience for the token.
    #audience = <None>

    # The auth_method must use the authentication method specified by the
    # Authorization Server. The system supports 5 authentication methods such
    # as tls_client_auth, client_secret_basic, client_secret_post,
    # client_secret_jwt, private_key_jwt.
    #auth_method = client_secret_basic

    # The OAuth 2.0 Client Identifier valid at the Authorization Server.
    #client_id = <None>

    # The OAuth 2.0 client secret. When the auth_method is client_secret_basic,
    # client_secret_post, or client_secret_jwt, the value is used, and
    # otherwise the value is ignored.
    #client_secret = <None>

    # If the access token generated by the Authorization Server is bound to the
    # OAuth 2.0 certificate thumbprint, the value can be set to true, and then
    # the keystone middleware will verify the thumbprint.
    #thumbprint_verify = False

    # The jwt_key_file must use the certificate key file which has been
    # registered with the Authorization Server. When the auth_method is
    # private_key_jwt, the value is used, and otherwise the value is ignored.
    #jwt_key_file = <None>

    # The jwt_algorithm must use the algorithm specified by the Authorization
    # Server. When the auth_method is client_secret_jwt, this value is often
    # set to HS256, when the auth_method is private_key_jwt, the value is often
    # set to RS256, and otherwise the value is ignored.
    #jwt_algorithm = <None>

    # This value is used to calculate the expiration time. If after the
    # expiration time, the access token can not be accepted. When the
    # auth_method is client_secret_jwt or private_key_jwt, the value is used,
    # and otherwise the value is ignored.
    #jwt_bearer_time_out = 3600

    # Specifies the method for obtaining the project ID that currently needs
    # to be accessed.
    #mapping_project_id = <None>

    # Specifies the method for obtaining the project name that currently needs
    # to be accessed.
    #mapping_project_name = <None>

    # Specifies the method for obtaining the project domain ID that currently
    # needs to be accessed.
    #mapping_project_domain_id = <None>

    # Specifies the method for obtaining the project domain name that currently
    # needs to be accessed.
    #mapping_project_domain_name = <None>

    # Specifies the method for obtaining the user ID.
    #mapping_user_id = client_id

    # Specifies the method for obtaining the user name.
    #mapping_user_name = username

    # Specifies the method for obtaining the domain ID which the user belongs.
    #mapping_user_domain_id = <None>

    # Specifies the method for obtaining the domain name which the user
    # belongs.
    #mapping_user_domain_name = <None>

    # Specifies the method for obtaining the list of roles in a project or
    # domain owned by the user.
    #mapping_roles = <None>

    # Specifies the method for obtaining the scope information indicating
    # whether a token is system-scoped.
    #mapping_system_scope = <None>

    # Specifies the method for obtaining the token expiration time.
    #mapping_expires_at = <None>

    # Optionally specify a list of memcached server(s) to use for caching.
    # If left undefined, tokens will instead be cached in-process.
    #memcached_servers = <None>

    # In order to prevent excessive effort spent validating tokens, the
    # middleware caches previously-seen tokens for a configurable duration
    # (in seconds). Set to -1 to disable caching completely.
    #token_cache_time = 300

    # (Optional) If defined, indicate whether token data should be
    # authenticated or authenticated and encrypted. If MAC, token data is
    # authenticated (with HMAC) in the cache. If ENCRYPT, token data is
    # encrypted and authenticated in the cache. If the value is not one of
    # these options or empty, auth_token will raise an exception on
    # initialization.
    #memcache_security_strategy = <None>

    # (Optional, mandatory if memcache_security_strategy is defined)
    # This string is used for key derivation.
    #memcache_secret_key = <None>

    # (Optional) Number of seconds memcached server is considered dead before
    # it is tried again.
    #memcache_pool_dead_retry = 5 * 60

    # (Optional) Maximum total number of open connections to every memcached
    # server.
    #memcache_pool_maxsize = 10

    # (Optional) Socket timeout in seconds for communicating with a memcached
    # server.
    #memcache_pool_socket_timeout = 3

    # (Optional) Number of seconds a connection to memcached is held unused in
    # the pool before it is closed.
    #memcache_pool_unused_timeout = 60

    # (Optional) Number of seconds that an operation will wait to get a
    # memcached client connection from the pool.
    #memcache_pool_conn_get_timeout = 10

    # (Optional) Use the advanced (eventlet safe) memcached client pool.
    #memcache_use_advanced_pool = True

Improving response time
-----------------------

Validating the identity of every client on every request can impact performance
for both the OpenStack service and the identity service. As a result,
keystonemiddleware is configurable to cache authentication responses from the
identity service in-memory. It is worth noting that tokens invalidated after
they've been stored in the cache may continue to work. Deployments using
`memcached`_ may use the following keystonemiddleware configuration options
instead of an in-memory cache.

* ``memcached_servers``: (optional) if defined, the memcached server(s) to use
  for caching. It will be ignored if Swift MemcacheRing is used instead.
* ``token_cache_time``: (optional, default 300 seconds) Set to -1 to disable
  caching completely.

When deploying auth_token middleware with Swift, user may elect
to use Swift MemcacheRing instead of the local Keystone memcache.
The Swift MemcacheRing object is passed in from the request environment
and it defaults to 'swift.cache'. However it could be
different, depending on deployment. To use Swift MemcacheRing, you must
provide the ``cache`` option.

* ``cache``: (optional) if defined, the environment key where the Swift
  MemcacheRing object is stored.

Memcached dependencies
======================

In order to use `memcached`_ it is necessary to install the `python-memcached`_
library. If data stored in `memcached`_ will need to be encrypted it is also
necessary to install the `pycrypto`_ library. These libs are not listed in
the requirements.txt file.

.. _`memcached`: http://memcached.org/
.. _`python-memcached`: https://pypi.org/project/python-memcached
.. _`pycrypto`: https://pypi.org/project/pycrypto

Memcache Protection
===================

When using `memcached`_, tokens and authentication responses are stored in the
cache as raw data. In the event the cache is compromised, all token and
authentication responses will be readable. To mitigate this risk,
``auth_token`` middleware provides an option to authenticate and optionally
encrypt the token data stored in the cache.

* ``memcache_security_strategy``: (optional) if defined, indicate
  whether token data should be authenticated or authenticated and
  encrypted. Acceptable values are ``MAC`` or ``ENCRYPT``. If ``MAC``,
  token data is authenticated (with HMAC) in the cache. If
  ``ENCRYPT``, token data is encrypted and authenticated in the
  cache. If the value is not one of these options or empty,
  ``auth_token`` will raise an exception on initialization.
* ``memcache_secret_key``: (optional, mandatory if
  ``memcache_security_strategy`` is defined) this string is used for
  key derivation. If ``memcache_security_strategy`` is defined and
  ``memcache_secret_key`` is absent, ``auth_token`` will raise an
  exception on initialization.

Exchanging User Information
===========================

The middleware expects to find a token representing the user with the header
``X-Auth-Token`` or ``X-Storage-Token``. `X-Storage-Token` is supported for
swift/cloud files and for legacy Rackspace use. If the token isn't present and
the middleware is configured to not delegate auth responsibility, it will
respond to the HTTP request with HTTPUnauthorized, returning the header
``WWW-Authenticate`` with the value `Keystone uri='...'` to indicate where to
request a token. The URI returned is configured with the
``www_authenticate_uri`` option.

The authentication middleware extends the HTTP request with the header
``X-Identity-Status``.  If a request is successfully authenticated, the value
is set to `Confirmed`. If the middleware is delegating the auth decision to the
service, then the status is set to `Invalid` if the auth request was
unsuccessful.

An ``X-Service-Token`` header may also be included with a request. If present,
and the value of ``X-Auth-Token`` or ``X-Storage-Token`` has not caused the
request to be denied, then the middleware will attempt to validate the value of
``X-Service-Token``. If valid, the authentication middleware extends the HTTP
request with the header ``X-Service-Identity-Status`` having value `Confirmed`
and also extends the request with additional headers representing the identity
authenticated and authorised by the token.

If ``X-Service-Token`` is present and its value is invalid and the
``delay_auth_decision`` option is True then the value of
``X-Service-Identity-Status`` is set to `Invalid` and no further headers are
added. Otherwise if ``X-Service-Token`` is present and its value is invalid
then the middleware will respond to the HTTP request with HTTPUnauthorized,
regardless of the validity of the ``X-Auth-Token`` or ``X-Storage-Token``
values.

Extended the request with additional User Information
-----------------------------------------------------

:py:class:`keystonemiddleware.auth_token.AuthProtocol` extends the
request with additional information if the user has been authenticated. See the
"What we add to the request for use by the OpenStack service" section in
:py:mod:`keystonemiddleware.auth_token` for the list of fields set by
the auth_token middleware.


References
==========

.. [PEP-333] pep0333 Phillip J Eby.  'Python Web Server Gateway Interface
    v1.0.''  http://www.python.org/dev/peps/pep-0333/.
