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

import mock
import testtools
import webob

from keystonemiddleware import auth_token
from keystonemiddleware.auth_token import _request


class FakeApp(object):

    @webob.dec.wsgify
    def __call__(self, req):
        return webob.Response()


class BaseAuthProtocolTests(testtools.TestCase):

    @mock.patch.multiple(auth_token._BaseAuthProtocol,
                         process_request=mock.DEFAULT,
                         process_response=mock.DEFAULT)
    def test_process_flow(self, process_request, process_response):
        m = auth_token._BaseAuthProtocol(FakeApp())

        process_request.return_value = None
        process_response.side_effect = lambda x: x

        req = webob.Request.blank('/', method='GET')
        resp = req.get_response(m)

        self.assertEqual(200, resp.status_code)

        self.assertEqual(1, process_request.call_count)
        self.assertIsInstance(process_request.call_args[0][0],
                              _request._AuthTokenRequest)

        self.assertEqual(1, process_response.call_count)
        self.assertIsInstance(process_response.call_args[0][0], webob.Response)
