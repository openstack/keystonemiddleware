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
import os
import shutil
import stat
import uuid

import mock
import testtools

from keystonemiddleware import auth_token


class RevocationsTests(testtools.TestCase):

    def _check_with_list(self, revoked_list, token_ids):
        directory_name = '/tmp/%s' % uuid.uuid4().hex
        signing_directory = auth_token._SigningDirectory(directory_name)
        self.addCleanup(shutil.rmtree, directory_name)

        identity_server = mock.Mock()

        verify_result_obj = {
            'revoked': list({'id': r} for r in revoked_list)
        }
        cms_verify = mock.Mock(return_value=json.dumps(verify_result_obj))

        revocations = auth_token._Revocations(
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
        self.assertRaises(auth_token.InvalidToken,
                          self._check_with_list, revoked_tokens, token_ids)


class SigningDirectoryTests(testtools.TestCase):

    def test_directory_created_when_doesnt_exist(self):
        # When _SigningDirectory is created, if the directory doesn't exist
        # it's created with the expected permissions.
        tmp_name = uuid.uuid4().hex
        parent_directory = '/tmp/%s' % tmp_name
        directory_name = '/tmp/%s/%s' % ((tmp_name,) * 2)

        # Directories are created by __init__.
        auth_token._SigningDirectory(directory_name)
        self.addCleanup(shutil.rmtree, parent_directory)

        self.assertTrue(os.path.isdir(directory_name))
        self.assertTrue(os.access(directory_name, os.W_OK))
        self.assertEqual(os.stat(directory_name).st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(os.stat(directory_name).st_mode),
                         stat.S_IRWXU)

    def test_use_directory_already_exists(self):
        # The directory can already exist.

        tmp_name = uuid.uuid4().hex
        parent_directory = '/tmp/%s' % tmp_name
        directory_name = '/tmp/%s/%s' % ((tmp_name,) * 2)
        os.makedirs(directory_name, stat.S_IRWXU)
        self.addCleanup(shutil.rmtree, parent_directory)

        auth_token._SigningDirectory(directory_name)

    def test_write_file(self):
        # write_file when the file doesn't exist creates the file.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_name = self.getUniqueString()
        contents = self.getUniqueString()
        signing_directory.write_file(file_name, contents)

        file_path = signing_directory.calc_path(file_name)
        with open(file_path) as f:
            actual_contents = f.read()

        self.assertEqual(contents, actual_contents)

    def test_replace_file(self):
        # write_file when the file already exists overwrites it.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_name = self.getUniqueString()
        orig_contents = self.getUniqueString()
        signing_directory.write_file(file_name, orig_contents)

        new_contents = self.getUniqueString()
        signing_directory.write_file(file_name, new_contents)

        file_path = signing_directory.calc_path(file_name)
        with open(file_path) as f:
            actual_contents = f.read()

        self.assertEqual(new_contents, actual_contents)

    def test_recreate_directory(self):
        # If the original directory is lost, it gets recreated when a file
        # is written.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        # Delete the directory.
        shutil.rmtree(signing_directory._directory_name)

        file_name = self.getUniqueString()
        contents = self.getUniqueString()
        signing_directory.write_file(file_name, contents)

        actual_contents = signing_directory.read_file(file_name)
        self.assertEqual(contents, actual_contents)

    def test_read_file(self):
        # Can read a file that was written.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_name = self.getUniqueString()
        contents = self.getUniqueString()
        signing_directory.write_file(file_name, contents)

        actual_contents = signing_directory.read_file(file_name)

        self.assertEqual(contents, actual_contents)

    def test_read_file_doesnt_exist(self):
        # Show what happens when try to read a file that wasn't written.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_name = self.getUniqueString()
        self.assertRaises(IOError, signing_directory.read_file, file_name)

    def test_calc_path(self):
        # calc_path returns the actual filename built from the directory name.

        signing_directory = auth_token._SigningDirectory()
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_name = self.getUniqueString()
        actual_path = signing_directory.calc_path(file_name)
        expected_path = os.path.join(signing_directory._directory_name,
                                     file_name)
        self.assertEqual(expected_path, actual_path)
