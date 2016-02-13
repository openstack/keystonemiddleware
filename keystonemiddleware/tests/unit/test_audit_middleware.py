#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import tempfile
import uuid

import mock
from oslo_config import cfg
from testtools import matchers
import webob

from keystonemiddleware import audit
from keystonemiddleware.tests.unit import utils


class FakeApp(object):
    def __call__(self, env, start_response):
        body = 'Some response'
        start_response('200 OK', [
            ('Content-Type', 'text/plain'),
            ('Content-Length', str(sum(map(len, body))))
        ])
        return [body]


class FakeFailingApp(object):
    def __call__(self, env, start_response):
        raise Exception('It happens!')


class BaseAuditMiddlewareTest(utils.BaseTestCase):
    def setUp(self):
        super(BaseAuditMiddlewareTest, self).setUp()
        self.fd, self.audit_map = tempfile.mkstemp()

        with open(self.audit_map, "w") as f:
            f.write("[custom_actions]\n")
            f.write("reboot = start/reboot\n")
            f.write("os-migrations/get = read\n\n")
            f.write("[path_keywords]\n")
            f.write("action = None\n")
            f.write("os-hosts = host\n")
            f.write("os-migrations = None\n")
            f.write("reboot = None\n")
            f.write("servers = server\n\n")
            f.write("[service_endpoints]\n")
            f.write("compute = service/compute")

        cfg.CONF([], project='keystonemiddleware')

        self.middleware = audit.AuditMiddleware(
            FakeApp(), audit_map_file=self.audit_map,
            service_name='pycadf')

        self.addCleanup(lambda: os.close(self.fd))
        self.addCleanup(cfg.CONF.reset)

    @staticmethod
    def get_environ_header(req_type):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"adminURL":
                                           "http://admin_host:8774",
                                           "region": "RegionOne",
                                           "publicURL":
                                           "http://public_host:8774",
                                           "internalURL":
                                           "http://internal_host:8774",
                                           "id": "resource_id"}],
                           "type": "compute",
                           "name": "nova"},]''',
                       'HTTP_X_USER_ID': 'user_id',
                       'HTTP_X_USER_NAME': 'user_name',
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': 'tenant_id',
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed'}
        env_headers['REQUEST_METHOD'] = req_type
        return env_headers


@mock.patch('oslo_messaging.get_transport', mock.MagicMock())
class AuditMiddlewareTest(BaseAuditMiddlewareTest):

    def test_api_request(self):
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            self.middleware(req)
            # Check first notification with only 'request'
            call_args = notify.call_args_list[0][0]
            self.assertEqual('audit.http.request', call_args[1])
            self.assertEqual('/foo/bar', call_args[2]['requestPath'])
            self.assertEqual('pending', call_args[2]['outcome'])
            self.assertNotIn('reason', call_args[2])
            self.assertNotIn('reporterchain', call_args[2])

            # Check second notification with request + response
            call_args = notify.call_args_list[1][0]
            self.assertEqual('audit.http.response', call_args[1])
            self.assertEqual('/foo/bar', call_args[2]['requestPath'])
            self.assertEqual('success', call_args[2]['outcome'])
            self.assertIn('reason', call_args[2])
            self.assertIn('reporterchain', call_args[2])

    def test_api_request_failure(self):
        self.middleware = audit.AuditMiddleware(
            FakeFailingApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            try:
                self.middleware(req)
                self.fail('Application exception has not been re-raised')
            except Exception:
                pass
            # Check first notification with only 'request'
            call_args = notify.call_args_list[0][0]
            self.assertEqual('audit.http.request', call_args[1])
            self.assertEqual('/foo/bar', call_args[2]['requestPath'])
            self.assertEqual('pending', call_args[2]['outcome'])
            self.assertNotIn('reporterchain', call_args[2])

            # Check second notification with request + response
            call_args = notify.call_args_list[1][0]
            self.assertEqual('audit.http.response', call_args[1])
            self.assertEqual('/foo/bar', call_args[2]['requestPath'])
            self.assertEqual('unknown', call_args[2]['outcome'])
            self.assertIn('reporterchain', call_args[2])

    def test_process_request_fail(self):
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.Notifier.info',
                        side_effect=Exception('error')) as notify:
            self.middleware._process_request(req)
            self.assertTrue(notify.called)

    def test_process_response_fail(self):
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.Notifier.info',
                        side_effect=Exception('error')) as notify:
            self.middleware._process_response(req, webob.response.Response())
            self.assertTrue(notify.called)

    def test_ignore_req_opt(self):
        self.middleware = audit.AuditMiddleware(FakeApp(),
                                                audit_map_file=self.audit_map,
                                                ignore_req_list='get, PUT')
        req = webob.Request.blank('/skip/foo',
                                  environ=self.get_environ_header('GET'))
        req1 = webob.Request.blank('/skip/foo',
                                   environ=self.get_environ_header('PUT'))
        req2 = webob.Request.blank('/accept/foo',
                                   environ=self.get_environ_header('POST'))
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            # Check GET/PUT request does not send notification
            self.middleware(req)
            self.middleware(req1)
            self.assertEqual([], notify.call_args_list)

            # Check non-GET/PUT request does send notification
            self.middleware(req2)
            self.assertThat(notify.call_args_list, matchers.HasLength(2))
            call_args = notify.call_args_list[0][0]
            self.assertEqual('audit.http.request', call_args[1])
            self.assertEqual('/accept/foo', call_args[2]['requestPath'])

            call_args = notify.call_args_list[1][0]
            self.assertEqual('audit.http.response', call_args[1])
            self.assertEqual('/accept/foo', call_args[2]['requestPath'])

    def test_api_request_no_messaging(self):
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        with mock.patch('keystonemiddleware.audit.messaging', None):
            with mock.patch('keystonemiddleware.audit._LOG.info') as log:
                self.middleware(req)
                # Check first notification with only 'request'
                call_args = log.call_args_list[0][0]
                self.assertEqual('audit.http.request',
                                 call_args[1]['event_type'])

                # Check second notification with request + response
                call_args = log.call_args_list[1][0]
                self.assertEqual('audit.http.response',
                                 call_args[1]['event_type'])

    def test_cadf_event_context_scoped(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            middleware(req)

            self.assertEqual(2, notify.call_count)
            first, second = [a[0] for a in notify.call_args_list]

            # the Context is the first argument. Let's verify it.
            self.assertIsInstance(first[0], dict)

            # ensure exact same context is used between request and response
            self.assertIs(first[0], second[0])

    def test_cadf_event_scoped_to_request(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            middleware(req)
            self.assertIsNotNone(req.environ.get('cadf_event'))

            # ensure exact same event is used between request and response
            self.assertEqual(notify.call_args_list[0][0][2]['id'],
                             notify.call_args_list[1][0][2]['id'])

    def test_cadf_event_scoped_to_request_on_error(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.Notifier.info',
                        side_effect=Exception('error')) as notify:
            middleware._process_request(req)
            self.assertTrue(notify.called)
        req2 = webob.Request.blank('/foo/bar',
                                   environ=self.get_environ_header('GET'))
        req2.context = {}
        with mock.patch('oslo_messaging.Notifier.info') as notify:
            middleware._process_response(req2, webob.response.Response())
            self.assertTrue(notify.called)
            # ensure event is not the same across requests
            self.assertNotEqual(req.environ['cadf_event'].id,
                                notify.call_args_list[0][0][2]['id'])


def _get_transport(conf, aliases=None, url=None):
    transport = mock.MagicMock()
    transport.conf = conf
    conf.register_opts = mock.MagicMock()
    return transport


@mock.patch('oslo_messaging.get_transport', side_effect=_get_transport)
class AuditNotifierConfigTest(BaseAuditMiddlewareTest):

    def test_conf_middleware_log_and_default_as_messaging(self, t):
        cfg.CONF.notification_driver = ['messaging']  # MultiOptStr value
        cfg.CONF.audit_middleware_notifications.driver = 'log'
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.notify._impl_log.LogDriver.notify',
                        side_effect=Exception('error')) as driver:
            middleware._process_request(req)
            # audit middleware conf has 'log' make sure that driver is invoked
            # and not the one specified in DEFAULT section
            self.assertTrue(driver.called)

    def test_conf_middleware_log_and_oslo_msg_as_messaging(self, t):
        cfg.CONF.notification_driver = None
        cfg.CONF.oslo_messaging_notifications.driver = ['messaging']
        cfg.CONF.audit_middleware_notifications.driver = 'log'
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.notify._impl_log.LogDriver.notify',
                        side_effect=Exception('error')) as driver:
            middleware._process_request(req)
            # audit middleware conf has 'log' make sure that driver is invoked
            # and not the one specified in oslo_messaging_notifications section
            self.assertTrue(driver.called)

    def test_conf_middleware_messaging_and_oslo_msg_as_log(self, t):
        cfg.CONF.notification_driver = None
        cfg.CONF.oslo_messaging_notifications.driver = ['log']
        cfg.CONF.audit_middleware_notifications.driver = 'messaging'
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.notify.messaging.MessagingDriver'
                        '.notify',
                        side_effect=Exception('error')) as driver:
            # audit middleware has 'messaging' make sure that driver is invoked
            # and not the one specified in oslo_messaging_notifications section
            middleware._process_request(req)
            self.assertTrue(driver.called)

    def test_with_no_middleware_notification_conf(self, t):
        cfg.CONF.notification_driver = None
        cfg.CONF.oslo_messaging_notifications.driver = ['messaging']
        cfg.CONF.audit_middleware_notifications.driver = None
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self.get_environ_header('GET'))
        req.context = {}
        with mock.patch('oslo_messaging.notify.messaging.MessagingDriver'
                        '.notify',
                        side_effect=Exception('error')) as driver:
            # audit middleware section is not set. So driver needs to be
            # invoked from oslo_messaging_notifications section.
            middleware._process_request(req)
            self.assertTrue(driver.called)

    def test_conf_middleware_messaging_and_transport_set(self, mock_transport):
        transport_url = 'rabbit://me:passwd@host:5672/virtual_host'
        cfg.CONF.audit_middleware_notifications.driver = 'messaging'
        cfg.CONF.audit_middleware_notifications.transport_url = transport_url

        audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        self.assertTrue(mock_transport.called)
        # make sure first call kwarg 'url' is same as provided transport_url
        self.assertEqual(transport_url,
                         mock_transport.call_args_list[0][1]['url'])


@mock.patch('oslo_messaging.rpc', mock.MagicMock())
class AuditApiLogicTest(BaseAuditMiddlewareTest):

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
            FakeApp(), audit_map_file=self.audit_map,
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
