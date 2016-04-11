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

import logging
import os
import stat
import tempfile

import six

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.i18n import _, _LI, _LW

_LOG = logging.getLogger(__name__)


class SigningDirectory(object):

    def __init__(self, directory_name=None, log=None):
        self._log = log or _LOG

        self._directory_name = directory_name
        if self._directory_name:
            self._log.info(
                _LI('Using %s as cache directory for signing certificate'),
                self._directory_name)
            self._verify_signing_dir()

    def write_file(self, file_name, new_contents):

        # In Python2, encoding is slow so the following check avoids it if it
        # is not absolutely necessary.
        if isinstance(new_contents, six.text_type):
            new_contents = new_contents.encode('utf-8')

        def _atomic_write():
            with tempfile.NamedTemporaryFile(dir=self._directory_name,
                                             delete=False) as f:
                f.write(new_contents)
            os.rename(f.name, self.calc_path(file_name))

        try:
            _atomic_write()
        except (OSError, IOError):
            self._verify_signing_dir()
            _atomic_write()

    def read_file(self, file_name):
        path = self.calc_path(file_name)
        open_kwargs = {'encoding': 'utf-8'} if six.PY3 else {}
        with open(path, 'r', **open_kwargs) as f:
            return f.read()

    def calc_path(self, file_name):
        self._lazy_create_signing_dir()
        return os.path.join(self._directory_name, file_name)

    def _lazy_create_signing_dir(self):
        if self._directory_name is None:
            self._directory_name = tempfile.mkdtemp(prefix='keystone-signing-')
            self._log.info(
                _LI('Using %s as cache directory for signing certificate'),
                self._directory_name)
            self._verify_signing_dir()

    def _verify_signing_dir(self):
        if os.path.isdir(self._directory_name):
            if not os.access(self._directory_name, os.W_OK):
                raise exc.ConfigurationError(
                    _('unable to access signing_dir %s') %
                    self._directory_name)
            uid = os.getuid()
            if os.stat(self._directory_name).st_uid != uid:
                self._log.warning(_LW('signing_dir is not owned by %s'), uid)
            current_mode = stat.S_IMODE(os.stat(self._directory_name).st_mode)
            if current_mode != stat.S_IRWXU:
                self._log.warning(
                    _LW('signing_dir mode is %(mode)s instead of %(need)s'),
                    {'mode': oct(current_mode), 'need': oct(stat.S_IRWXU)})
        else:
            os.makedirs(self._directory_name, stat.S_IRWXU)
