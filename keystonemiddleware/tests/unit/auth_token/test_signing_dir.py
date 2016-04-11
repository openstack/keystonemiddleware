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

import os
import shutil
import stat
import uuid

from keystonemiddleware.auth_token import _signing_dir
from keystonemiddleware.tests.unit import utils


class SigningDirectoryTests(utils.BaseTestCase):

    def test_directory_created_when_doesnt_exist(self):
        # When _SigningDirectory is created, if the directory doesn't exist
        # it's created with the expected permissions.
        tmp_name = uuid.uuid4().hex
        parent_directory = '/tmp/%s' % tmp_name
        directory_name = '/tmp/%s/%s' % ((tmp_name,) * 2)

        # Directories are created by __init__.
        _signing_dir.SigningDirectory(directory_name)
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

        _signing_dir.SigningDirectory(directory_name)

    def test_write_file(self):
        # write_file when the file doesn't exist creates the file.

        signing_directory = _signing_dir.SigningDirectory()

        file_name = self.getUniqueString()
        contents = self.getUniqueString()
        signing_directory.write_file(file_name, contents)

        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        file_path = signing_directory.calc_path(file_name)
        with open(file_path) as f:
            actual_contents = f.read()

        self.assertEqual(contents, actual_contents)

    def test_replace_file(self):
        # write_file when the file already exists overwrites it.

        signing_directory = _signing_dir.SigningDirectory()

        file_name = self.getUniqueString()
        orig_contents = self.getUniqueString()
        signing_directory.write_file(file_name, orig_contents)

        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        new_contents = self.getUniqueString()
        signing_directory.write_file(file_name, new_contents)

        file_path = signing_directory.calc_path(file_name)
        with open(file_path) as f:
            actual_contents = f.read()

        self.assertEqual(new_contents, actual_contents)

    def test_recreate_directory(self):
        # If the original directory is lost, it gets recreated when a file
        # is written.

        signing_directory = _signing_dir.SigningDirectory()
        original_file_name = self.getUniqueString()
        original_contents = self.getUniqueString()
        signing_directory.write_file(original_file_name, original_contents)

        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        # Delete the directory.
        shutil.rmtree(signing_directory._directory_name)

        new_file_name = self.getUniqueString()
        new_contents = self.getUniqueString()
        signing_directory.write_file(new_file_name, new_contents)

        actual_contents = signing_directory.read_file(new_file_name)
        self.assertEqual(new_contents, actual_contents)

    def test_read_file(self):
        # Can read a file that was written.

        signing_directory = _signing_dir.SigningDirectory()
        file_name = self.getUniqueString()
        contents = self.getUniqueString()
        signing_directory.write_file(file_name, contents)

        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        actual_contents = signing_directory.read_file(file_name)

        self.assertEqual(contents, actual_contents)

    def test_read_file_doesnt_exist(self):
        # Show what happens when try to read a file that wasn't written.

        signing_directory = _signing_dir.SigningDirectory()

        file_name = self.getUniqueString()
        self.assertRaises(IOError, signing_directory.read_file, file_name)
        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

    def test_calc_path(self):
        # calc_path returns the actual filename built from the directory name.

        signing_directory = _signing_dir.SigningDirectory()

        file_name = self.getUniqueString()
        actual_path = signing_directory.calc_path(file_name)

        self.addCleanup(shutil.rmtree, signing_directory._directory_name)

        expected_path = os.path.join(signing_directory._directory_name,
                                     file_name)
        self.assertEqual(expected_path, actual_path)
