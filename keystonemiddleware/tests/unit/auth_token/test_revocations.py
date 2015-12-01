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

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.auth_token import _revocations
from keystonemiddleware.auth_token import _signing_dir
from keystonemiddleware.tests.unit import utils


class RevocationsTests(utils.BaseTestCase):

    def _setup_revocations(self, revoked_list):
        directory_name = '/tmp/%s' % uuid.uuid4().hex
        signing_directory = _signing_dir.SigningDirectory(directory_name)
        self.addCleanup(shutil.rmtree, directory_name)

        identity_server = mock.Mock()

        verify_result_obj = {'revoked': revoked_list}
        cms_verify = mock.Mock(return_value=json.dumps(verify_result_obj))

        revocations = _revocations.Revocations(
            timeout=datetime.timedelta(1), signing_directory=signing_directory,
            identity_server=identity_server, cms_verify=cms_verify)
        return revocations

    def _check_with_list(self, revoked_list, token_ids):
        revoked_list = list({'id': r} for r in revoked_list)
        revocations = self._setup_revocations(revoked_list)
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

    def test_check_by_audit_id_revoked(self):
        # When the audit ID is in the revocation list, InvalidToken is raised.
        audit_id = uuid.uuid4().hex
        revoked_list = [{'id': uuid.uuid4().hex, 'audit_id': audit_id}]
        revocations = self._setup_revocations(revoked_list)
        self.assertRaises(exc.InvalidToken,
                          revocations.check_by_audit_id, [audit_id])

    def test_check_by_audit_id_chain_revoked(self):
        # When the token's audit chain ID is in the revocation list,
        # InvalidToken is raised.
        revoked_audit_id = uuid.uuid4().hex
        revoked_list = [{'id': uuid.uuid4().hex, 'audit_id': revoked_audit_id}]
        revocations = self._setup_revocations(revoked_list)

        token_audit_ids = [uuid.uuid4().hex, revoked_audit_id]
        self.assertRaises(exc.InvalidToken,
                          revocations.check_by_audit_id, token_audit_ids)

    def test_check_by_audit_id_not_revoked(self):
        # When the audit ID is not in the revocation list no exception.
        revoked_list = [{'id': uuid.uuid4().hex, 'audit_id': uuid.uuid4().hex}]
        revocations = self._setup_revocations(revoked_list)

        audit_id = uuid.uuid4().hex
        revocations.check_by_audit_id([audit_id])

    def test_check_by_audit_id_no_audit_ids(self):
        # Older identity servers don't send audit_ids in the revocation list.
        # When this happens, check_by_audit_id still works, just doesn't
        # verify anything.
        revoked_list = [{'id': uuid.uuid4().hex}]
        revocations = self._setup_revocations(revoked_list)

        audit_id = uuid.uuid4().hex
        revocations.check_by_audit_id([audit_id])
