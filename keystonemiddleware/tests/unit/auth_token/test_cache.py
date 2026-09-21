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

import random
import uuid

import fixtures
from unittest import mock

from keystonemiddleware.auth_token import _cache
from keystonemiddleware.auth_token import _crypt as crypt
from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.tests.unit.auth_token import base
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import BASE_URI
from keystonemiddleware.tests.unit.auth_token.test_auth_token_middleware \
    import FAKE_ADMIN_TOKEN_ID
from keystonemiddleware.tests.unit import utils

MEMCACHED_SERVERS = ['localhost:11211']
MEMCACHED_AVAILABLE = None


class TestTokenSerializer(base.BaseAuthTokenTestCase):

    def setUp(self):
        super(TestTokenSerializer, self).setUp()
        self.serializer = _cache.TokenSerializer(mock.Mock())

    def test_fixed_cache_key_length(self):
        short_string = uuid.uuid4().hex
        long_string = 8 * uuid.uuid4().hex

        hashed_short_string_key, short_context = \
            self.serializer.get_cache_key(short_string)
        hashed_long_string_key, long_context = \
            self.serializer.get_cache_key(long_string)

        # The hash keys should always match in length
        self.assertEqual(len(hashed_short_string_key),
                         len(hashed_long_string_key))
        self.assertIsNone(short_context)
        self.assertIsNone(long_context)

    def test_get_cache_key(self):
        cache_key, context = self.serializer.get_cache_key('token_id')
        self.assertTrue(cache_key.startswith('tokens/'))
        self.assertEqual(
            'tokens/'
            'ca88682941bde45de2864ecd5fe6f1598ea2382c6ac3f8c217adbbe9fae52456',
            cache_key)
        self.assertIsNone(context)

        # Repeated operation should generate the same key
        self.assertEqual(
            cache_key,
            self.serializer.get_cache_key('token_id')[0]
        )

        # Generated key should be different if token_id is different
        self.assertNotEqual(
            cache_key,
            self.serializer.get_cache_key('different_token_id')[0]
        )

    def test_serialize_deserialize(self):
        _, context = self.serializer.get_cache_key('token_id')
        data = bytearray(random.randbytes(10))

        # Serialized data should match the original data
        serialized = self.serializer.serialize(data, context)
        self.assertEqual(data, serialized)

        # Serialized data should be de-serialized
        deserialized = self.serializer.deserialize(serialized, context)
        self.assertEqual(data, deserialized)


class TestSecureTokenSerializer(base.BaseAuthTokenTestCase):

    def setUp(self):
        super(TestSecureTokenSerializer, self).setUp()
        self.secret_key = uuid.uuid4().hex
        self.serializer = _cache.SecureTokenSerializer(
            mock.Mock(), 'encrypt', self.secret_key)

    def test_get_cache_key(self):
        cache_key, context = self.serializer.get_cache_key('token_id')
        self.assertTrue(cache_key.startswith('tokens/'))
        self.assertNotEqual(
            'tokens/'
            'ca88682941bde45de2864ecd5fe6f1598ea2382c6ac3f8c217adbbe9fae52456',
            cache_key,
        )
        self.assertIsNotNone(context)

        # Repeated operation should generate the same key
        self.assertEqual(
            cache_key,
            self.serializer.get_cache_key('token_id')[0]
        )
        # Generated key should be different if token_id is different
        self.assertNotEqual(
            cache_key,
            self.serializer.get_cache_key('different_token_id')[0]
        )

    def test_serialize_deserialize(self):
        _, context = self.serializer.get_cache_key('token_id')
        data = bytearray(random.randbytes(10))

        # Serialized data should not match the original data
        serialized = self.serializer.serialize(data, context)
        self.assertNotEqual(data, serialized)

        # Serialized data should be de-serialized
        deserialized = self.serializer.deserialize(serialized, context)
        self.assertEqual(data, deserialized)

        # Corrupted cache results in None
        self.assertIsNone(
            self.serializer.deserialize(serialized[:-1], context),
        )


class TestCacheSetup(base.BaseAuthTokenTestCase):

    def test_assert_valid_memcache_protection_config(self):
        # test missing memcache_secret_key
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'Encrypt'
        }
        self.assertRaises(exc.ConfigurationError,
                          self.create_simple_middleware,
                          conf=conf)
        # test invalue memcache_security_strategy
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'whatever'
        }
        self.assertRaises(exc.ConfigurationError,
                          self.create_simple_middleware,
                          conf=conf)
        # test missing memcache_secret_key
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mac'
        }
        self.assertRaises(exc.ConfigurationError,
                          self.create_simple_middleware,
                          conf=conf)
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'Encrypt',
            'memcache_secret_key': ''
        }
        self.assertRaises(exc.ConfigurationError,
                          self.create_simple_middleware,
                          conf=conf)
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mAc',
            'memcache_secret_key': ''
        }
        self.assertRaises(exc.ConfigurationError,
                          self.create_simple_middleware,
                          conf=conf)


class NoMemcacheAuthToken(base.BaseAuthTokenTestCase):
    """These tests will not have the memcache module available."""

    def setUp(self):
        super(NoMemcacheAuthToken, self).setUp()
        self.useFixture(utils.DisableModuleFixture('memcache'))

    def test_nomemcache(self):
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'www_authenticate_uri': 'https://keystone.example.com:1234',
        }

        self.create_simple_middleware(conf=conf)


class TestLiveMemcache(base.BaseAuthTokenTestCase):

    def setUp(self):
        super(TestLiveMemcache, self).setUp()

        global MEMCACHED_AVAILABLE

        if MEMCACHED_AVAILABLE is None:
            try:
                import memcache
                c = memcache.Client(MEMCACHED_SERVERS)
                c.set('ping', 'pong', time=1)
                MEMCACHED_AVAILABLE = c.get('ping') == 'pong'
            except ImportError:
                MEMCACHED_AVAILABLE = False

        if not MEMCACHED_AVAILABLE:
            self.skipTest('memcached not available')

    def test_encrypt_cache_data(self):
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'encrypt',
            'memcache_secret_key': 'mysecret'
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})

        token_cache.set(token, data)
        self.assertEqual(token_cache.get(token), data)

    @mock.patch("keystonemiddleware.auth_token._crypt.unprotect_data")
    def test_corrupted_cache_data(self, mocked_decrypt_data):
        mocked_decrypt_data.side_effect = crypt.InvalidMacError(
            "Invalid MAC; data appears to be corrupted.")

        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'encrypt',
            'memcache_secret_key': 'mysecret'
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})

        token_cache.set(token, data)
        self.assertIsNone(token_cache.get(token))

    @mock.patch("keystonemiddleware.auth_token._crypt.unprotect_data")
    def test_cache_data_failed_to_decrypt(self, mocked_decrypt_data):
        mocked_decrypt_data.side_effect = Exception('something is wrong')

        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'encrypt',
            'memcache_secret_key': 'mysecret'
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})

        token_cache.set(token, data)
        self.assertIsNone(token_cache.get(token))

    def test_sign_cache_data(self):
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_security_strategy': 'mac',
            'memcache_secret_key': 'mysecret'
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})

        token_cache.set(token, data)
        self.assertEqual(token_cache.get(token), data)

    def test_no_memcache_protection(self):
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_secret_key': 'mysecret'
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})
        token_cache.set(token, data)
        self.assertEqual(token_cache.get(token), data)

    def test_memcache_pool(self):
        conf = {
            'auth_type': 'admin_token',
            'endpoint': '%s/v3' % BASE_URI,
            'token': FAKE_ADMIN_TOKEN_ID,
            'memcached_servers': ','.join(MEMCACHED_SERVERS),
            'memcache_use_advanced_pool': True
        }

        token = uuid.uuid4().hex.encode()
        data = uuid.uuid4().hex

        token_cache = self.create_simple_middleware(conf=conf)._token_cache
        token_cache.initialize({})

        token_cache.set(token, data)
        self.assertEqual(token_cache.get(token), data)


class TestMemcachePoolAbstraction(utils.TestCase):
    def setUp(self):
        super(TestMemcachePoolAbstraction, self).setUp()
        self.useFixture(fixtures.MockPatch(
            'oslo_cache._memcache_pool._MemcacheClient'))

    def test_abstraction_layer_reserve_places_connection_back_in_pool(self):
        cache_pool = _cache._MemcacheClientPool(
            memcache_servers=[], arguments={}, maxsize=1, unused_timeout=10)
        conn = None
        with cache_pool.reserve() as client:
            self.assertEqual(cache_pool._pool._acquired, 1)
            conn = client

        self.assertEqual(cache_pool._pool._acquired, 0)
        with cache_pool.reserve() as client:
            # Make sure the connection we got before is in-fact the one we
            # get again.
            self.assertEqual(conn, client)
