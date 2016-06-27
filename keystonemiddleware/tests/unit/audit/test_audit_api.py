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

import mock
from pycadf import cadftaxonomy as taxonomy
import webob

from keystonemiddleware import audit
from keystonemiddleware.tests.unit.audit import base


@mock.patch('oslo_messaging.rpc', mock.MagicMock())
class AuditApiLogicTest(base.BaseAuditMiddlewareTest):

    def api_request(self, method, url):
        req = webob.Request.blank(url, environ=self.get_environ_header(method),
                                  remote_addr='192.168.0.1')
        req.context = {}
        self.middleware._process_request(req)
        return req

    def test_get_list(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['action'], 'read/list')
        self.assertEqual(payload['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['eventType'], 'activity')
        self.assertEqual(payload['target']['name'], 'nova')
        self.assertEqual(payload['target']['id'], 'resource_id')
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(len(payload['target']['addresses']), 3)
        self.assertEqual(payload['target']['addresses'][0]['name'], 'admin')
        self.assertEqual(payload['target']['addresses'][0]['url'],
                         'http://admin_host:8774')
        self.assertEqual(payload['initiator']['id'], 'user_id')
        self.assertEqual(payload['initiator']['name'], 'user_name')
        self.assertEqual(payload['initiator']['project_id'],
                         'tenant_id')
        self.assertEqual(payload['initiator']['host']['address'],
                         '192.168.0.1')
        self.assertEqual(payload['initiator']['typeURI'],
                         'service/security/account/user')
        self.assertNotEqual(payload['initiator']['credential']['token'],
                            'token')
        self.assertEqual(payload['initiator']['credential']['identity_status'],
                         'Confirmed')
        self.assertNotIn('reason', payload)
        self.assertNotIn('reporterchain', payload)
        self.assertEqual(payload['observer']['id'], 'target')
        self.assertEqual(req.path, payload['requestPath'])

    def test_get_read(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers/'
                               + str(uuid.uuid4()))
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/server')
        self.assertEqual(payload['action'], 'read')
        self.assertEqual(payload['outcome'], 'pending')

    def test_get_unknown_endpoint(self):
        req = self.api_request('GET', 'http://unknown:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['action'], 'read/list')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['target']['name'], 'unknown')
        self.assertEqual(payload['target']['id'], 'unknown')
        self.assertEqual(payload['target']['typeURI'], 'unknown')

    def test_get_unknown_endpoint_default_set(self):
        with open(self.audit_map, "w") as f:
            f.write("[DEFAULT]\n")
            f.write("target_endpoint_type = compute\n")
            f.write("[path_keywords]\n")
            f.write("servers = server\n\n")
            f.write("[service_endpoints]\n")
            f.write("compute = service/compute")

        self.middleware = audit.AuditMiddleware(
            base.FakeApp(), audit_map_file=self.audit_map,
            service_name='pycadf')

        req = self.api_request('GET', 'http://unknown:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['action'], 'read/list')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['target']['name'], 'nova')
        self.assertEqual(payload['target']['id'], 'resource_id')
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')

    def test_put(self):
        req = self.api_request('PUT', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'update')
        self.assertEqual(payload['outcome'], 'pending')

    def test_delete(self):
        req = self.api_request('DELETE', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'delete')
        self.assertEqual(payload['outcome'], 'pending')

    def test_head(self):
        req = self.api_request('HEAD', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'read')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_update(self):
        req = self.api_request('POST',
                               'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers/'
                               + str(uuid.uuid4()))
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/server')
        self.assertEqual(payload['action'], 'update')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_create(self):
        req = self.api_request('POST', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'create')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_action(self):
        req = webob.Request.blank('http://admin_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers/action',
                                  environ=self.get_environ_header('POST'))
        req.body = b'{"createImage" : {"name" : "new-image","metadata": ' \
                   b'{"ImageType": "Gold","ImageVersion": "2.0"}}}'
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/action')
        self.assertEqual(payload['action'], 'update/createImage')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_empty_body_action(self):
        req = self.api_request('POST', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers/action')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/action')
        self.assertEqual(payload['action'], 'create')
        self.assertEqual(payload['outcome'], 'pending')

    def test_custom_action(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/os-hosts/'
                               + str(uuid.uuid4()) + '/reboot')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-hosts/host/reboot')
        self.assertEqual(payload['action'], 'start/reboot')
        self.assertEqual(payload['outcome'], 'pending')

    def test_custom_action_complex(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/os-migrations')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-migrations')
        self.assertEqual(payload['action'], 'read')
        req = self.api_request('POST', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/os-migrations')
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-migrations')
        self.assertEqual(payload['action'], 'create')

    def test_response_mod_msg(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        req.context = {}
        payload = req.environ['cadf_event'].as_dict()
        self.middleware._process_response(req, webob.Response())
        payload2 = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['id'], payload2['id'])
        self.assertEqual(payload['tags'], payload2['tags'])
        self.assertEqual(payload2['outcome'], 'success')
        self.assertEqual(payload2['reason']['reasonType'], 'HTTP')
        self.assertEqual(payload2['reason']['reasonCode'], '200')
        self.assertEqual(len(payload2['reporterchain']), 1)
        self.assertEqual(payload2['reporterchain'][0]['role'], 'modifier')
        self.assertEqual(payload2['reporterchain'][0]['reporter']['id'],
                         'target')

    def test_no_response(self):
        req = self.api_request('GET', 'http://admin_host:8774/v2/'
                               + str(uuid.uuid4()) + '/servers')
        req.context = {}
        payload = req.environ['cadf_event'].as_dict()
        self.middleware._process_response(req, None)
        payload2 = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['id'], payload2['id'])
        self.assertEqual(payload['tags'], payload2['tags'])
        self.assertEqual(payload2['outcome'], 'unknown')
        self.assertNotIn('reason', payload2)
        self.assertEqual(len(payload2['reporterchain']), 1)
        self.assertEqual(payload2['reporterchain'][0]['role'], 'modifier')
        self.assertEqual(payload2['reporterchain'][0]['reporter']['id'],
                         'target')

    def test_missing_req(self):
        req = webob.Request.blank('http://admin_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        self.assertNotIn('cadf_event', req.environ)
        self.middleware._process_response(req, webob.Response())
        self.assertIn('cadf_event', req.environ)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['outcome'], 'success')
        self.assertEqual(payload['reason']['reasonType'], 'HTTP')
        self.assertEqual(payload['reason']['reasonCode'], '200')
        self.assertEqual(payload['observer']['id'], 'target')

    def test_missing_catalog_endpoint_id(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"adminURL":
                                           "http://admin_host:8774",
                                           "region": "RegionOne",
                                           "publicURL":
                                           "http://public_host:8774",
                                           "internalURL":
                                           "http://internal_host:8774"}],
                           "type": "compute",
                           "name": "nova"},]''',
                       'HTTP_X_USER_ID': 'user_id',
                       'HTTP_X_USER_NAME': 'user_name',
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': 'tenant_id',
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}
        req = webob.Request.blank('http://admin_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers',
                                  environ=env_headers)
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['target']['id'], 'nova')

    def test_endpoint_missing_internal_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"adminURL":
                                           "http://admin_host:8774",
                                           "region": "RegionOne",
                                           "publicURL":
                                           "http://public_host:8774"}],
                            "type": "compute",
                            "name": "nova"},]''',
                       'HTTP_X_USER_ID': 'user_id',
                       'HTTP_X_USER_NAME': 'user_name',
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': 'tenant_id',
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}
        req = webob.Request.blank('http://admin_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers',
                                  environ=env_headers)
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual((payload['target']['addresses'][1]['url']), "unknown")

    def test_endpoint_missing_public_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"adminURL":
                                           "http://admin_host:8774",
                                           "region": "RegionOne",
                                           "internalURL":
                                           "http://internal_host:8774"}],
                            "type": "compute",
                            "name": "nova"},]''',
                       'HTTP_X_USER_ID': 'user_id',
                       'HTTP_X_USER_NAME': 'user_name',
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': 'tenant_id',
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}
        req = webob.Request.blank('http://admin_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers',
                                  environ=env_headers)
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual((payload['target']['addresses'][2]['url']), "unknown")

    def test_endpoint_missing_admin_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"region": "RegionOne",
                                           "publicURL":
                                           "http://public_host:8774",
                                           "internalURL":
                                           "http://internal_host:8774"}],
                            "type": "compute",
                            "name": "nova"},]''',
                       'HTTP_X_USER_ID': 'user_id',
                       'HTTP_X_USER_NAME': 'user_name',
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': 'tenant_id',
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}
        req = webob.Request.blank('http://public_host:8774/v2/'
                                  + str(uuid.uuid4()) + '/servers',
                                  environ=env_headers)
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual((payload['target']['addresses'][0]['url']), "unknown")

    def test_no_auth_token(self):
        # Test cases where API requests such as Swift list public containers
        # which does not require an auth token. In these cases, CADF event
        # should have the defaults (i.e taxonomy.UNKNOWN) instead of raising
        # an exception.
        env_headers = {'HTTP_X_IDENTITY_STATUS': 'Invalid',
                       'REQUEST_METHOD': 'GET'}
        req = webob.Request.blank('https://23.253.72.207/v1/'
                                  + str(uuid.uuid4()),
                                  environ=env_headers,
                                  remote_addr='192.168.0.1')
        req.context = {}
        self.middleware._process_request(req)
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['action'], 'read')
        self.assertEqual(payload['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['eventType'], 'activity')
        self.assertEqual(payload['target']['name'], taxonomy.UNKNOWN)
        self.assertEqual(payload['target']['id'], taxonomy.UNKNOWN)
        self.assertEqual(payload['target']['typeURI'], taxonomy.UNKNOWN)
        self.assertNotIn('addresses', payload['target'])
        self.assertEqual(payload['initiator']['id'], taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['name'], taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['project_id'],
                         taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['host']['address'],
                         '192.168.0.1')
        self.assertEqual(payload['initiator']['typeURI'],
                         'service/security/account/user')
        self.assertNotEqual(payload['initiator']['credential']['token'],
                            None)
        self.assertEqual(payload['initiator']['credential']['identity_status'],
                         'Invalid')
        self.assertNotIn('reason', payload)
        self.assertNotIn('reporterchain', payload)
        self.assertEqual(payload['observer']['id'], 'target')
        self.assertEqual(req.path, payload['requestPath'])
