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
import hashlib

from oslo_serialization import jsonutils
import six

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _memcache_crypt as memcache_crypt
from keystonemiddleware.auth_token import _memcache_pool as memcache_pool
from keystonemiddleware.i18n import _, _LE, _LW
from keystonemiddleware.openstack.common import memorycache


def _hash_key(key):
    """Turn a set of arguments into a SHA256 hash.

    Using a known-length cache key is important to ensure that memcache
    maximum key length is not exceeded causing failures to validate.
    """
    if isinstance(key, six.text_type):
        # NOTE(morganfainberg): Ensure we are always working with a bytes
        # type required for the hasher. In python 2.7 it is possible to
        # get a text_type (unicode). In python 3.4 all strings are
        # text_type and not bytes by default. This encode coerces the
        # text_type to the appropriate bytes values.
        key = key.encode('utf-8')
    return hashlib.sha256(key).hexdigest()


class _EnvCachePool(object):
    """A cache pool that has been passed through ENV variables."""

    def __init__(self, cache):
        self._environment_cache = cache

    @contextlib.contextmanager
    def reserve(self):
        """Context manager to manage a pooled cache reference."""
        yield self._environment_cache


class _CachePool(list):
    """A lazy pool of cache references."""

    def __init__(self, memcached_servers, log):
        self._memcached_servers = memcached_servers
        if not self._memcached_servers:
            log.warning(_LW(
                "Using the in-process token cache is deprecated as of the "
                "4.2.0 release and may be removed in the 5.0.0 release or "
                "the 'O' development cycle. The in-process cache causes "
                "inconsistent results and high memory usage. When the feature "
                "is removed the auth_token middleware will not cache tokens "
                "by default which may result in performance issues. It is "
                "recommended to use  memcache for the auth_token token cache "
                "by setting the memcached_servers option."))

    @contextlib.contextmanager
    def reserve(self):
        """Context manager to manage a pooled cache reference."""
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
    def __init__(self, memcache_servers, **kwargs):
        self._pool = memcache_pool.MemcacheClientPool(memcache_servers,
                                                      **kwargs)

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

    def __init__(self, log, cache_time=None,
                 env_cache_name=None, memcached_servers=None,
                 use_advanced_pool=False, **kwargs):
        self._LOG = log
        self._cache_time = cache_time
        self._env_cache_name = env_cache_name
        self._memcached_servers = memcached_servers
        self._use_advanced_pool = use_advanced_pool
        self._memcache_pool_options = kwargs

        self._cache_pool = None
        self._initialized = False

    def _get_cache_pool(self, cache):
        if cache:
            return _EnvCachePool(cache)

        elif self._use_advanced_pool and self._memcached_servers:
            return _MemcacheClientPool(self._memcached_servers,
                                       **self._memcache_pool_options)

        else:
            return _CachePool(self._memcached_servers, self._LOG)

    def initialize(self, env):
        if self._initialized:
            return

        self._cache_pool = self._get_cache_pool(env.get(self._env_cache_name))
        self._initialized = True

    def store(self, token_id, data):
        """Put token data into the cache."""
        self._LOG.debug('Storing token in cache')
        self._cache_store(token_id, data)

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
        return self._CACHE_KEY_TEMPLATE % _hash_key(token_id), unused_context

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

    def get(self, token_id):
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

        if isinstance(serialized, six.text_type):
            serialized = serialized.encode('utf8')
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

        # NOTE(jamielennox): Cached values used to be stored as a tuple of data
        # and expiry time. They no longer are but we have to allow some time to
        # transition the old format so if it's a tuple just return the data.
        try:
            data, expires = cached
        except ValueError:
            data = cached

        return data

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
