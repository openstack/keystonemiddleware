# Copyright (c) 2014 OpenStack Foundation.
#
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

import pkg_resources
from testtools import matchers

from keystonemiddleware import opts
from keystonemiddleware.tests import utils


class OptsTestCase(utils.TestCase):

    def _test_list_auth_token_opts(self, result):
        self.assertThat(result, matchers.HasLength(1))

        for group in (g for (g, _l) in result):
            self.assertEqual('keystone_authtoken', group)

        expected_opt_names = [
            'auth_admin_prefix',
            'auth_host',
            'auth_port',
            'auth_protocol',
            'auth_uri',
            'identity_uri',
            'auth_version',
            'delay_auth_decision',
            'http_connect_timeout',
            'http_request_max_retries',
            'admin_token',
            'admin_user',
            'admin_password',
            'admin_tenant_name',
            'cache',
            'certfile',
            'keyfile',
            'cafile',
            'insecure',
            'signing_dir',
            'memcached_servers',
            'token_cache_time',
            'revocation_cache_time',
            'memcache_security_strategy',
            'memcache_secret_key',
            'include_service_catalog',
            'enforce_token_bind',
            'check_revocations_for_cached',
            'hash_algorithms'
        ]
        opt_names = [o.name for (g, l) in result for o in l]
        self.assertThat(opt_names, matchers.HasLength(len(expected_opt_names)))

        for opt in opt_names:
            self.assertIn(opt, expected_opt_names)

    def test_list_auth_token_opts(self):
        self._test_list_auth_token_opts(opts.list_auth_token_opts())

    def test_entry_point(self):
        result = None
        for ep in pkg_resources.iter_entry_points('oslo.config.opts'):
            if ep.name == 'keystonemiddleware.auth_token':
                list_fn = ep.load()
                result = list_fn()
                break

        self.assertIsNotNone(result)
        self._test_list_auth_token_opts(result)
