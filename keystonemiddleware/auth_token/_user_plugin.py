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

from keystoneauth1.identity import base as base_identity


class _TokenData(object):
    """An abstraction to show auth_token consumers some of the token contents.

    This is a simplified and cleaned up keystoneclient.access.AccessInfo object
    with which services relying on auth_token middleware can find details of
    the current token.
    """

    def __init__(self, auth_ref):
        self._stored_auth_ref = auth_ref

    @property
    def _is_v2(self):
        return self._stored_auth_ref.version == 'v2.0'

    @property
    def auth_token(self):
        """The token data used to authenticate requests.

        :returns: token data.
        :rtype: str
        """
        return self._stored_auth_ref.auth_token

    @property
    def user_id(self):
        """The user id associated with the authentication request.

        :rtype: str
        """
        return self._stored_auth_ref.user_id

    @property
    def user_domain_id(self):
        """The domain ID of the user associated with the authentication.

        Returns the domain id of the user associated with the authentication
        request.

        :returns: str
        """
        # NOTE(jamielennox): v2 AccessInfo returns 'default' for domain_id
        # because it can't know that value. We want to return None instead.
        if self._is_v2:
            return None

        return self._stored_auth_ref.user_domain_id

    @property
    def project_id(self):
        """The project ID associated with the authentication.

        :rtype: str
        """
        return self._stored_auth_ref.project_id

    @property
    def project_domain_id(self):
        """The ID of the project associated with the authentication.

        The domain id of the project associated with the authentication
        request.

        :rtype: str
        """
        # NOTE(jamielennox): v2 AccessInfo returns 'default' for domain_id
        # because it can't know that value. We want to return None instead.
        if self._is_v2:
            return None

        return self._stored_auth_ref.project_domain_id

    @property
    def domain_id(self):
        """The domain ID the authentication is scoped to.

        :rtype: str
        """
        return self._stored_auth_ref.domain_id

    @property
    def trust_id(self):
        """Returns the trust id associated with the authentication request..

        :rtype: str
        """
        return self._stored_auth_ref.trust_id

    @property
    def trustor_user_id(self):
        """The trustor id associated with the authentication request.

        :rtype: str
        """
        return self._stored_auth_ref.trustor_user_id

    @property
    def trustee_user_id(self):
        """The trustee id associated with the authentication request.

        :rtype: str
        """
        return self._stored_auth_ref.trustee_user_id

    @property
    def role_ids(self):
        """Role ids of the user associated with the authentication request.

        :rtype: set(str)
        """
        return frozenset(self._stored_auth_ref.role_ids or [])

    @property
    def role_names(self):
        """Role names of the user associated with the authentication request.

        :rtype: set(str)
        """
        return frozenset(self._stored_auth_ref.role_names or [])

    @property
    def _log_format(self):
        roles = ','.join(self.role_names)
        return 'user_id %s, project_id %s, roles %s' % (self.user_id,
                                                        self.project_id,
                                                        roles)


class UserAuthPlugin(base_identity.BaseIdentityPlugin):
    """The incoming authentication credentials.

    A plugin that represents the incoming user credentials. This can be
    consumed by applications.

    This object is not expected to be constructed directly by users. It is
    created and passed by auth_token middleware and then can be used as the
    authentication plugin when communicating via a session.
    """

    def __init__(self, user_auth_ref, serv_auth_ref):
        super(UserAuthPlugin, self).__init__(reauthenticate=False)

        # NOTE(jamielennox): _user_auth_ref and _serv_auth_ref are private
        # because this object ends up in the environ that is passed to the
        # service, however they are used within auth_token middleware.
        self._user_auth_ref = user_auth_ref
        self._serv_auth_ref = serv_auth_ref

        self._user_data = None
        self._serv_data = None

    @property
    def has_user_token(self):
        """Did this authentication request contained a user auth token."""
        return self._user_auth_ref is not None

    @property
    def user(self):
        """Authentication information about the user token.

        Will return None if a user token was not passed with this request.
        """
        if not self.has_user_token:
            return None

        if not self._user_data:
            self._user_data = _TokenData(self._user_auth_ref)

        return self._user_data

    @property
    def has_service_token(self):
        """Did this authentication request contained a service token."""
        return self._serv_auth_ref is not None

    @property
    def service(self):
        """Authentication information about the service token.

        Will return None if a user token was not passed with this request.
        """
        if not self.has_service_token:
            return None

        if not self._serv_data:
            self._serv_data = _TokenData(self._serv_auth_ref)

        return self._serv_data

    def get_auth_ref(self, session, **kwargs):
        # NOTE(jamielennox): We will always use the auth_ref that was
        # calculated by the middleware. reauthenticate=False in __init__ should
        # ensure that this function is only called on the first access.
        return self._user_auth_ref

    @property
    def _log_format(self):
        msg = []

        if self.has_user_token:
            msg.append('user: %s' % self.user._log_format)

        if self.has_service_token:
            msg.append('service: %s' % self.service._log_format)

        return ' '.join(msg)
