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

import testtools

from keystonemiddleware.auth_token import _utils


class TokenEncodingTest(testtools.TestCase):

    def test_unquoted_token(self):
        self.assertEqual('foo%20bar', _utils.safe_quote('foo bar'))

    def test_quoted_token(self):
        self.assertEqual('foo%20bar', _utils.safe_quote('foo%20bar'))

    def test_messages_encoded_as_bytes(self):
        """Test that string are passed around as bytes for PY3."""
        msg = "This is an error"

        class FakeResp(_utils.MiniResp):
            def __init__(self, error, env):
                super(FakeResp, self).__init__(error, env)

        fake_resp = FakeResp(msg, dict(REQUEST_METHOD='GET'))
        # On Py2 .encode() don't do much but that's better than to
        # have a ifdef with six.PY3
        self.assertEqual(msg.encode(), fake_resp.body[0])
