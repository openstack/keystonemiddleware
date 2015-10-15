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

import functools

from keystoneauth1 import discover
from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import plugin
from keystoneclient import exceptions as ksc_exceptions
from keystoneclient.v2_0 import client as v2_client
from keystoneclient.v3 import client as v3_client
from six.moves import urllib

from keystonemiddleware.auth_token import _auth
from keystonemiddleware.auth_token import _exceptions as ksm_exceptions
from keystonemiddleware.i18n import _, _LE, _LI, _LW


def _convert_fetch_cert_exception(fetch_cert):
    @functools.wraps(fetch_cert)
    def wrapper(self):
        try:
            text = fetch_cert(self)
        except ksa_exceptions.HttpError as e:
            raise ksc_exceptions.CertificateConfigError(e.details)
        return text

    return wrapper


class _RequestStrategy(object):

    AUTH_VERSION = None

    def __init__(self, adap, include_service_catalog=None):
        self._include_service_catalog = include_service_catalog

    def verify_token(self, user_token):
        pass

    @_convert_fetch_cert_exception
    def fetch_signing_cert(self):
        return self._fetch_signing_cert()

    def _fetch_signing_cert(self):
        pass

    @_convert_fetch_cert_exception
    def fetch_ca_cert(self):
        return self._fetch_ca_cert()

    def _fetch_ca_cert(self):
        pass

    def fetch_revocation_list(self):
        pass


class _V2RequestStrategy(_RequestStrategy):

    AUTH_VERSION = (2, 0)

    def __init__(self, adap, **kwargs):
        super(_V2RequestStrategy, self).__init__(adap, **kwargs)
        self._client = v2_client.Client(session=adap)

    def verify_token(self, token):
        auth_ref = self._client.tokens.validate_access_info(token)

        if not auth_ref:
            msg = _('Failed to fetch token data from identity server')
            raise ksm_exceptions.InvalidToken(msg)

        return {'access': auth_ref}

    def _fetch_signing_cert(self):
        return self._client.certificates.get_signing_certificate()

    def _fetch_ca_cert(self):
        return self._client.certificates.get_ca_certificate()

    def fetch_revocation_list(self):
        return self._client.tokens.get_revoked()


class _V3RequestStrategy(_RequestStrategy):

    AUTH_VERSION = (3, 0)

    def __init__(self, adap, **kwargs):
        super(_V3RequestStrategy, self).__init__(adap, **kwargs)
        self._client = v3_client.Client(session=adap)

    def verify_token(self, token):
        auth_ref = self._client.tokens.validate(
            token,
            include_catalog=self._include_service_catalog)

        if not auth_ref:
            msg = _('Failed to fetch token data from identity server')
            raise ksm_exceptions.InvalidToken(msg)

        return {'token': auth_ref}

    def _fetch_signing_cert(self):
        return self._client.simple_cert.get_certificates()

    def _fetch_ca_cert(self):
        return self._client.simple_cert.get_ca_certificates()

    def fetch_revocation_list(self):
        return self._client.tokens.get_revoked()


_REQUEST_STRATEGIES = [_V3RequestStrategy, _V2RequestStrategy]


class IdentityServer(object):
    """Base class for operations on the Identity API server.

    The auth_token middleware needs to communicate with the Identity API server
    to validate UUID tokens, fetch the revocation list, signing certificates,
    etc. This class encapsulates the data and methods to perform these
    operations.

    """

    def __init__(self, log, adap, include_service_catalog=None,
                 requested_auth_version=None):
        self._LOG = log
        self._adapter = adap
        self._include_service_catalog = include_service_catalog
        self._requested_auth_version = requested_auth_version

        # Built on-demand with self._request_strategy.
        self._request_strategy_obj = None

    @property
    def auth_uri(self):
        auth_uri = self._adapter.get_endpoint(interface=plugin.AUTH_INTERFACE)

        # NOTE(jamielennox): This weird stripping of the prefix hack is
        # only relevant to the legacy case. We urljoin '/' to get just the
        # base URI as this is the original behaviour.
        if isinstance(self._adapter.auth, _auth.AuthTokenPlugin):
            auth_uri = urllib.parse.urljoin(auth_uri, '/').rstrip('/')

        return auth_uri

    @property
    def auth_version(self):
        return self._request_strategy.AUTH_VERSION

    @property
    def _request_strategy(self):
        if not self._request_strategy_obj:
            strategy_class = self._get_strategy_class()
            self._adapter.version = strategy_class.AUTH_VERSION

            self._request_strategy_obj = strategy_class(
                self._adapter,
                include_service_catalog=self._include_service_catalog)

        return self._request_strategy_obj

    def _get_strategy_class(self):
        if self._requested_auth_version:
            # A specific version was requested.
            if discover.version_match(_V3RequestStrategy.AUTH_VERSION,
                                      self._requested_auth_version):
                return _V3RequestStrategy

            # The version isn't v3 so we don't know what to do. Just assume V2.
            return _V2RequestStrategy

        # Specific version was not requested then we fall through to
        # discovering available versions from the server
        for klass in _REQUEST_STRATEGIES:
            if self._adapter.get_endpoint(version=klass.AUTH_VERSION):
                self._LOG.debug('Auth Token confirmed use of %s apis',
                                self._requested_auth_version)
                return klass

        versions = ['v%d.%d' % s.AUTH_VERSION for s in _REQUEST_STRATEGIES]
        self._LOG.error(_LE('No attempted versions [%s] supported by server'),
                        ', '.join(versions))

        msg = _('No compatible apis supported by server')
        raise ksm_exceptions.ServiceError(msg)

    def verify_token(self, user_token, retry=True):
        """Authenticate user token with identity server.

        :param user_token: user's token id
        :param retry: flag that forces the middleware to retry
                      user authentication when an indeterminate
                      response is received. Optional.
        :returns: access info received from identity server on success
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`
        :raises exc.InvalidToken: if token is rejected
        :raises exc.ServiceError: if unable to authenticate token

        """
        try:
            auth_ref = self._request_strategy.verify_token(user_token)
        except ksa_exceptions.NotFound as e:
            self._LOG.warning(_LW('Authorization failed for token'))
            self._LOG.warning(_LW('Identity response: %s'), e.response.text)
            raise ksm_exceptions.InvalidToken(_('Token authorization failed'))
        except ksa_exceptions.Unauthorized as e:
            self._LOG.info(_LI('Identity server rejected authorization'))
            self._LOG.warning(_LW('Identity response: %s'), e.response.text)
            if retry:
                self._LOG.info(_LI('Retrying validation'))
                return self.verify_token(user_token, False)
            msg = _('Identity server rejected authorization necessary to '
                    'fetch token data')
            raise ksm_exceptions.ServiceError(msg)
        except ksa_exceptions.HttpError as e:
            self._LOG.error(
                _LE('Bad response code while validating token: %s'),
                e.http_status)
            self._LOG.warning(_LW('Identity response: %s'), e.response.text)
            msg = _('Failed to fetch token data from identity server')
            raise ksm_exceptions.ServiceError(msg)
        else:
            return auth_ref

    def fetch_revocation_list(self):
        try:
            data = self._request_strategy.fetch_revocation_list()
        except ksa_exceptions.HttpError as e:
            msg = _('Failed to fetch token revocation list: %d')
            raise ksm_exceptions.RevocationListError(msg % e.http_status)
        if 'signed' not in data:
            msg = _('Revocation list improperly formatted.')
            raise ksm_exceptions.RevocationListError(msg)
        return data['signed']

    def fetch_signing_cert(self):
        return self._request_strategy.fetch_signing_cert()

    def fetch_ca_cert(self):
        return self._request_strategy.fetch_ca_cert()
