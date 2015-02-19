# Copyright 2014 IBM Corp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import datetime
import json
import shutil
import uuid

import mock
import testtools

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _revocations
from keystonemiddleware.auth_token import _signing_dir


class RevocationsTests(testtools.TestCase):

    def _check_with_list(self, revoked_list, token_ids):
        directory_name = '/tmp/%s' % uuid.uuid4().hex
        signing_directory = _signing_dir.SigningDirectory(directory_name)
        self.addCleanup(shutil.rmtree, directory_name)

        identity_server = mock.Mock()

        verify_result_obj = {
            'revoked': list({'id': r} for r in revoked_list)
        }
        cms_verify = mock.Mock(return_value=json.dumps(verify_result_obj))

        revocations = _revocations.Revocations(
            timeout=datetime.timedelta(1), signing_directory=signing_directory,
            identity_server=identity_server, cms_verify=cms_verify)

        revocations.check(token_ids)

    def test_check_empty_list(self):
        # When the identity server returns an empty list, a token isn't
        # revoked.

        revoked_tokens = []
        token_ids = [uuid.uuid4().hex]
        # No assert because this would raise
        self._check_with_list(revoked_tokens, token_ids)

    def test_check_revoked(self):
        # When the identity server returns a list with a token in it, that
        # token is revoked.

        token_id = uuid.uuid4().hex
        revoked_tokens = [token_id]
        token_ids = [token_id]
        self.assertRaises(exc.InvalidToken,
                          self._check_with_list, revoked_tokens, token_ids)
