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

import mock
from oslo.config import cfg
import testtools
from testtools import matchers
import webob

from keystonemiddleware import audit


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


@mock.patch('oslo.messaging.get_transport', mock.MagicMock())
class AuditMiddlewareTest(testtools.TestCase):

    def setUp(self):
        super(AuditMiddlewareTest, self).setUp()
        (self.fd, self.audit_map) = tempfile.mkstemp()
        cfg.CONF([], project='keystonemiddleware')

        self.addCleanup(lambda: os.close(self.fd))
        self.addCleanup(cfg.CONF.reset)

    @staticmethod
    def _get_environ_header(req_type):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                       '''[{"endpoints_links": [],
                            "endpoints": [{"adminURL":
                                           "http://host:8774/v2/admin",
                                           "region": "RegionOne",
                                           "publicURL":
                                           "http://host:8774/v2/public",
                                           "internalURL":
                                           "http://host:8774/v2/internal",
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

    def test_api_request(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self._get_environ_header('GET'))
        with mock.patch('oslo.messaging.Notifier.info') as notify:
            middleware(req)
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
        middleware = audit.AuditMiddleware(
            FakeFailingApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self._get_environ_header('GET'))
        with mock.patch('oslo.messaging.Notifier.info') as notify:
            try:
                middleware(req)
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
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self._get_environ_header('GET'))
        with mock.patch('oslo.messaging.Notifier.info',
                        side_effect=Exception('error')) as notify:
            middleware._process_request(req)
            self.assertTrue(notify.called)

    def test_process_response_fail(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self._get_environ_header('GET'))
        with mock.patch('oslo.messaging.Notifier.info',
                        side_effect=Exception('error')) as notify:
            middleware._process_response(req, webob.response.Response())
            self.assertTrue(notify.called)

    def test_ignore_req_opt(self):
        middleware = audit.AuditMiddleware(FakeApp(),
                                           audit_map_file=self.audit_map,
                                           ignore_req_list='get, PUT')
        req = webob.Request.blank('/skip/foo',
                                  environ=self._get_environ_header('GET'))
        req1 = webob.Request.blank('/skip/foo',
                                   environ=self._get_environ_header('PUT'))
        req2 = webob.Request.blank('/accept/foo',
                                   environ=self._get_environ_header('POST'))
        with mock.patch('oslo.messaging.Notifier.info') as notify:
            # Check GET/PUT request does not send notification
            middleware(req)
            middleware(req1)
            self.assertEqual([], notify.call_args_list)

            # Check non-GET/PUT request does send notification
            middleware(req2)
            self.assertThat(notify.call_args_list, matchers.HasLength(2))
            call_args = notify.call_args_list[0][0]
            self.assertEqual('audit.http.request', call_args[1])
            self.assertEqual('/accept/foo', call_args[2]['requestPath'])

            call_args = notify.call_args_list[1][0]
            self.assertEqual('audit.http.response', call_args[1])
            self.assertEqual('/accept/foo', call_args[2]['requestPath'])

    def test_api_request_no_messaging(self):
        middleware = audit.AuditMiddleware(
            FakeApp(),
            audit_map_file=self.audit_map,
            service_name='pycadf')
        req = webob.Request.blank('/foo/bar',
                                  environ=self._get_environ_header('GET'))
        with mock.patch('keystonemiddleware.audit.messaging', None):
            with mock.patch('keystonemiddleware.audit._LOG.info') as log:
                middleware(req)
                # Check first notification with only 'request'
                call_args = log.call_args_list[0][0]
                self.assertEqual('audit.http.request',
                                 call_args[1]['event_type'])

                # Check second notification with request + response
                call_args = log.call_args_list[1][0]
                self.assertEqual('audit.http.response',
                                 call_args[1]['event_type'])
