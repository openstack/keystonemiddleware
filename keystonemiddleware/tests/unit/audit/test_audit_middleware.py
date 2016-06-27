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

import uuid

import mock
from testtools import matchers
import webob

from keystonemiddleware import audit
from keystonemiddleware.tests.unit.audit import base


@mock.patch('oslo_messaging.get_transport', mock.MagicMock())
class AuditMiddlewareTest(base.BaseAuditMiddlewareTest):

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
            base.FakeFailingApp(),
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
        self.middleware = audit.AuditMiddleware(base.FakeApp(),
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
        with mock.patch('keystonemiddleware.audit._notifier.oslo_messaging',
                        None):
            with mock.patch('keystonemiddleware.audit._LOG.info') as log:
                self.middleware = audit.AuditMiddleware(
                    base.FakeApp(),
                    audit_map_file=self.audit_map)

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
            base.FakeApp(),
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
            base.FakeApp(),
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
            base.FakeApp(),
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

    def test_project_name_from_oslo_config(self):
        self.assertEqual(self.PROJECT_NAME,
                         self.middleware._conf.project)

    def test_project_name_from_local_config(self):
        project_name = uuid.uuid4().hex
        self.middleware = audit.AuditMiddleware(
            base.FakeApp(), audit_map_file=self.audit_map,
            service_name='pycadf', project=project_name)
        self.assertEqual(project_name, self.middleware._conf.project)

    def test_no_response(self):
        url = 'http://admin_host:8774/v2/' + str(uuid.uuid4()) + '/servers'
        req = webob.Request.blank(url,
                                  environ=self.get_environ_header('GET'),
                                  remote_addr='192.168.0.1')
        req.context = {}
        self.middleware._process_request(req)
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


def _get_transport(conf, aliases=None, url=None):
    transport = mock.MagicMock()
    transport.conf = conf
    conf.register_opts = mock.MagicMock()
    return transport


@mock.patch('oslo_messaging.get_transport', side_effect=_get_transport)
class AuditNotifierConfigTest(base.BaseAuditMiddlewareTest):

    def test_conf_middleware_log_and_default_as_messaging(self, t):
        self.cfg.config(driver='log', group='audit_middleware_notifications')
        middleware = audit.AuditMiddleware(
            base.FakeApp(),
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
        self.cfg.config(driver='messaging',
                        group='oslo_messaging_notifications')
        self.cfg.config(driver='log',
                        group='audit_middleware_notifications')
        middleware = audit.AuditMiddleware(
            base.FakeApp(),
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
        self.cfg.config(driver='log', group='oslo_messaging_notifications')
        self.cfg.config(driver='messaging',
                        group='audit_middleware_notifications')
        middleware = audit.AuditMiddleware(
            base.FakeApp(),
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
        self.cfg.config(driver='messaging',
                        group='oslo_messaging_notifications')
        self.cfg.config(driver=None, group='audit_middleware_notifications')

        middleware = audit.AuditMiddleware(
            base.FakeApp(),
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
        self.cfg.config(driver='messaging',
                        transport_url=transport_url,
                        group='audit_middleware_notifications')

        audit.AuditMiddleware(
            base.FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        self.assertTrue(mock_transport.called)
        # make sure first call kwarg 'url' is same as provided transport_url
        self.assertEqual(transport_url,
                         mock_transport.call_args_list[0][1]['url'])
