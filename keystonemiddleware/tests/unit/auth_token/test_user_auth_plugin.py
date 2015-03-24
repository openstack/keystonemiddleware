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

import uuid

from keystoneclient import auth
from keystoneclient import fixture

from keystonemiddleware.tests.unit.auth_token import base

# NOTE(jamielennox): just some sample values that we can use for testing
BASE_URI = 'https://keystone.example.com:1234'
AUTH_URL = 'https://keystone.auth.com:1234'


class BaseUserPluginTests(object):

    def configure_middleware(self,
                             auth_plugin,
                             group='keystone_authtoken',
                             **kwargs):
        opts = auth.get_plugin_class(auth_plugin).get_options()
        self.cfg.register_opts(opts, group=group)

        self.cfg.config(group=group,
                        auth_plugin=auth_plugin,
                        **kwargs)

    def assertTokenDataEqual(self, token_id, token, token_data):
        self.assertEqual(token_id, token_data.auth_token)
        self.assertEqual(token.user_id, token_data.user_id)
        try:
            trust_id = token.trust_id
        except KeyError:
            trust_id = None
        self.assertEqual(trust_id, token_data.trust_id)
        self.assertEqual(self.get_role_names(token), token_data.role_names)

    def get_plugin(self, token_id, service_token_id=None):
        headers = {'X-Auth-Token': token_id}

        if service_token_id:
            headers['X-Service-Token'] = service_token_id

        m = self.create_simple_middleware()

        resp = self.call(m, headers=headers)
        self.assertEqual(200, resp.status_int)
        return resp.request.environ['keystone.token_auth']

    def test_user_information(self):
        token_id, token = self.get_token()
        plugin = self.get_plugin(token_id)

        self.assertTokenDataEqual(token_id, token, plugin.user)
        self.assertFalse(plugin.has_service_token)
        self.assertIsNone(plugin.service)

    def test_with_service_information(self):
        token_id, token = self.get_token()
        service_id, service = self.get_token()

        plugin = self.get_plugin(token_id, service_id)

        self.assertTokenDataEqual(token_id, token, plugin.user)
        self.assertTokenDataEqual(service_id, service, plugin.service)


class V2UserPluginTests(BaseUserPluginTests, base.BaseAuthTokenTestCase):

    def setUp(self):
        super(V2UserPluginTests, self).setUp()

        self.service_token = fixture.V2Token()
        self.service_token.set_scope()
        s = self.service_token.add_service('identity', name='keystone')

        s.add_endpoint(public=BASE_URI,
                       admin=BASE_URI,
                       internal=BASE_URI)

        self.configure_middleware(auth_plugin='v2password',
                                  auth_url='%s/v2.0/' % AUTH_URL,
                                  user_id=self.service_token.user_id,
                                  password=uuid.uuid4().hex,
                                  tenant_id=self.service_token.tenant_id)

        auth_discovery = fixture.DiscoveryList(href=AUTH_URL, v3=False)
        self.requests_mock.get(AUTH_URL, json=auth_discovery)

        base_discovery = fixture.DiscoveryList(href=BASE_URI, v3=False)
        self.requests_mock.get(BASE_URI, json=base_discovery)

        url = '%s/v2.0/tokens' % AUTH_URL
        self.requests_mock.post(url, json=self.service_token)

    def get_role_names(self, token):
        return set(x['name'] for x in token['access']['user'].get('roles', []))

    def get_token(self):
        token = fixture.V2Token()
        token.set_scope()
        token.add_role()

        request_headers = {'X-Auth-Token': self.service_token.token_id}

        url = '%s/v2.0/tokens/%s' % (BASE_URI, token.token_id)
        self.requests_mock.get(url,
                               request_headers=request_headers,
                               json=token)

        return token.token_id, token

    def assertTokenDataEqual(self, token_id, token, token_data):
        super(V2UserPluginTests, self).assertTokenDataEqual(token_id,
                                                            token,
                                                            token_data)

        self.assertEqual(token.tenant_id, token_data.project_id)
        self.assertIsNone(token_data.user_domain_id)
        self.assertIsNone(token_data.project_domain_id)


class V3UserPluginTests(BaseUserPluginTests, base.BaseAuthTokenTestCase):

    def setUp(self):
        super(V3UserPluginTests, self).setUp()

        self.service_token_id = uuid.uuid4().hex
        self.service_token = fixture.V3Token()
        s = self.service_token.add_service('identity', name='keystone')
        s.add_standard_endpoints(public=BASE_URI,
                                 admin=BASE_URI,
                                 internal=BASE_URI)

        self.configure_middleware(auth_plugin='v3password',
                                  auth_url='%s/v3/' % AUTH_URL,
                                  user_id=self.service_token.user_id,
                                  password=uuid.uuid4().hex,
                                  project_id=self.service_token.project_id)

        auth_discovery = fixture.DiscoveryList(href=AUTH_URL)
        self.requests_mock.get(AUTH_URL, json=auth_discovery)

        base_discovery = fixture.DiscoveryList(href=BASE_URI)
        self.requests_mock.get(BASE_URI, json=base_discovery)

        self.requests_mock.post(
            '%s/v3/auth/tokens' % AUTH_URL,
            headers={'X-Subject-Token': self.service_token_id},
            json=self.service_token)

    def get_role_names(self, token):
        return set(x['name'] for x in token['token'].get('roles', []))

    def get_token(self):
        token_id = uuid.uuid4().hex
        token = fixture.V3Token()
        token.set_project_scope()
        token.add_role()

        request_headers = {'X-Auth-Token': self.service_token_id,
                           'X-Subject-Token': token_id}
        headers = {'X-Subject-Token': token_id}

        self.requests_mock.get('%s/v3/auth/tokens' % BASE_URI,
                               request_headers=request_headers,
                               headers=headers,
                               json=token)

        return token_id, token

    def assertTokenDataEqual(self, token_id, token, token_data):
        super(V3UserPluginTests, self).assertTokenDataEqual(token_id,
                                                            token,
                                                            token_data)

        self.assertEqual(token.user_domain_id, token_data.user_domain_id)
        self.assertEqual(token.project_id, token_data.project_id)
        self.assertEqual(token.project_domain_id, token_data.project_domain_id)
