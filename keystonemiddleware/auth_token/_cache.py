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

import contextlib

from keystoneclient.common import cms
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _memcache_crypt as memcache_crypt
from keystonemiddleware.i18n import _, _LE
from keystonemiddleware.openstack.common import memorycache


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


class TokenCache(object):
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

        :raises exc.InvalidToken: if the token is invalid

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

        If token is invalid raise exc.InvalidToken
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
            raise exc.InvalidToken(_('Token authorization failed'))

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
            raise exc.InvalidToken(_('Token authorization failed'))

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


class SecureTokenCache(TokenCache):
    """A token cache that stores tokens encrypted.

    A more secure version of TokenCache that will encrypt tokens before
    caching them.
    """

    def __init__(self, log, security_strategy, secret_key, **kwargs):
        super(SecureTokenCache, self).__init__(log, **kwargs)

        security_strategy = security_strategy.upper()

        if security_strategy not in ('MAC', 'ENCRYPT'):
            msg = _('memcache_security_strategy must be ENCRYPT or MAC')
            raise exc.ConfigurationError(msg)
        if not secret_key:
            msg = _('memcache_secret_key must be defined when a '
                    'memcache_security_strategy is defined')
            raise exc.ConfigurationError(msg)

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
