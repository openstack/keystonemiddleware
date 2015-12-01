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

import datetime
import logging
import os

from oslo_serialization import jsonutils
from oslo_utils import timeutils

from keystonemiddleware.auth_token import _exceptions as exc
from keystonemiddleware.i18n import _

_LOG = logging.getLogger(__name__)


class Revocations(object):
    _FILE_NAME = 'revoked.pem'

    def __init__(self, timeout, signing_directory, identity_server,
                 cms_verify, log=_LOG):
        self._cache_timeout = timeout
        self._signing_directory = signing_directory
        self._identity_server = identity_server
        self._cms_verify = cms_verify
        self._log = log

        self._fetched_time_prop = None
        self._list_prop = None

    @property
    def _fetched_time(self):
        if not self._fetched_time_prop:
            # If the fetched list has been written to disk, use its
            # modification time.
            file_path = self._signing_directory.calc_path(self._FILE_NAME)
            if os.path.exists(file_path):
                mtime = os.path.getmtime(file_path)
                fetched_time = datetime.datetime.utcfromtimestamp(mtime)
            # Otherwise the list will need to be fetched.
            else:
                fetched_time = datetime.datetime.min
            self._fetched_time_prop = fetched_time
        return self._fetched_time_prop

    @_fetched_time.setter
    def _fetched_time(self, value):
        self._fetched_time_prop = value

    def _fetch(self):
        revocation_list_data = self._identity_server.fetch_revocation_list()
        return self._cms_verify(revocation_list_data)

    @property
    def _list(self):
        timeout = self._fetched_time + self._cache_timeout
        list_is_current = timeutils.utcnow() < timeout

        if list_is_current:
            # Load the list from disk if required
            if not self._list_prop:
                self._list_prop = jsonutils.loads(
                    self._signing_directory.read_file(self._FILE_NAME))
        else:
            self._list = self._fetch()
        return self._list_prop

    @_list.setter
    def _list(self, value):
        """Save a revocation list to memory and to disk.

        :param value: A json-encoded revocation list

        """
        self._list_prop = jsonutils.loads(value)
        self._fetched_time = timeutils.utcnow()
        self._signing_directory.write_file(self._FILE_NAME, value)

    def _is_revoked(self, token_id):
        """Indicate whether the token_id appears in the revocation list."""
        revoked_tokens = self._list.get('revoked', None)
        if not revoked_tokens:
            return False

        revoked_ids = (x['id'] for x in revoked_tokens)
        return token_id in revoked_ids

    def _any_revoked(self, token_ids):
        for token_id in token_ids:
            if self._is_revoked(token_id):
                return True
        return False

    def check(self, token_ids):
        if self._any_revoked(token_ids):
            self._log.debug('Token is marked as having been revoked')
            raise exc.InvalidToken(_('Token has been revoked'))

    def check_by_audit_id(self, audit_ids):
        """Check whether the audit_id appears in the revocation list.

        :raises keystonemiddleware.auth_token._exceptions.InvalidToken:
            if the audit ID(s) appear in the revocation list.

        """
        revoked_tokens = self._list.get('revoked', None)
        if not revoked_tokens:
            # There's no revoked tokens, so nothing to do.
            return

        # The audit_id may not be present in the revocation events because
        # earlier versions of the identity server didn't provide them.
        revoked_ids = set(
            x['audit_id'] for x in revoked_tokens if 'audit_id' in x)
        for audit_id in audit_ids:
            if audit_id in revoked_ids:
                self._log.debug(
                    'Token is marked as having been revoked by audit id')
                raise exc.InvalidToken(_('Token has been revoked'))
