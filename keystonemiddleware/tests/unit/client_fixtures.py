# Copyright 2013 OpenStack Foundation
#
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

import fixtures
from keystoneauth1 import fixture
from keystoneclient.common import cms
from keystoneclient import utils
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six
import testresources


TESTDIR = os.path.dirname(os.path.abspath(__file__))
ROOTDIR = os.path.normpath(os.path.join(TESTDIR, '..', '..', '..'))
CERTDIR = os.path.join(ROOTDIR, 'examples', 'pki', 'certs')
CMSDIR = os.path.join(ROOTDIR, 'examples', 'pki', 'cms')
KEYDIR = os.path.join(ROOTDIR, 'examples', 'pki', 'private')


def _hash_signed_token_safe(signed_text, **kwargs):
    if isinstance(signed_text, six.text_type):
        signed_text = signed_text.encode('utf-8')
    return utils.hash_signed_token(signed_text, **kwargs)


class Examples(fixtures.Fixture):
    """Example tokens and certs loaded from the examples directory.

    To use this class correctly, the module needs to override the test suite
    class to use testresources.OptimisingTestSuite (otherwise the files will
    be read on every test). This is done by defining a load_tests function
    in the module, like this:

    def load_tests(loader, tests, pattern):
        return testresources.OptimisingTestSuite(tests)

    (see http://docs.python.org/2/library/unittest.html#load-tests-protocol )

    """

    def setUp(self):
        super(Examples, self).setUp()

        # The data for several tests are signed using openssl and are stored in
        # files in the signing subdirectory.  In order to keep the values
        # consistent between the tests and the signed documents, we read them
        # in for use in the tests.
        with open(os.path.join(CMSDIR, 'auth_token_scoped.json')) as f:
            self.TOKEN_SCOPED_DATA = cms.cms_to_token(f.read())

        with open(os.path.join(CMSDIR, 'auth_token_scoped.pem')) as f:
            self.SIGNED_TOKEN_SCOPED = cms.cms_to_token(f.read())
        self.SIGNED_TOKEN_SCOPED_HASH = _hash_signed_token_safe(
            self.SIGNED_TOKEN_SCOPED)
        self.SIGNED_TOKEN_SCOPED_HASH_SHA256 = _hash_signed_token_safe(
            self.SIGNED_TOKEN_SCOPED, mode='sha256')
        with open(os.path.join(CMSDIR, 'auth_token_unscoped.pem')) as f:
            self.SIGNED_TOKEN_UNSCOPED = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_v3_token_scoped.pem')) as f:
            self.SIGNED_v3_TOKEN_SCOPED = cms.cms_to_token(f.read())
        self.SIGNED_v3_TOKEN_SCOPED_HASH = _hash_signed_token_safe(
            self.SIGNED_v3_TOKEN_SCOPED)
        self.SIGNED_v3_TOKEN_SCOPED_HASH_SHA256 = _hash_signed_token_safe(
            self.SIGNED_v3_TOKEN_SCOPED, mode='sha256')
        with open(os.path.join(CMSDIR, 'auth_token_revoked.pem')) as f:
            self.REVOKED_TOKEN = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_token_scoped_expired.pem')) as f:
            self.SIGNED_TOKEN_SCOPED_EXPIRED = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_v3_token_revoked.pem')) as f:
            self.REVOKED_v3_TOKEN = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_token_scoped.pkiz')) as f:
            self.SIGNED_TOKEN_SCOPED_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_token_unscoped.pkiz')) as f:
            self.SIGNED_TOKEN_UNSCOPED_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_v3_token_scoped.pkiz')) as f:
            self.SIGNED_v3_TOKEN_SCOPED_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_token_revoked.pkiz')) as f:
            self.REVOKED_TOKEN_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR,
                               'auth_token_scoped_expired.pkiz')) as f:
            self.SIGNED_TOKEN_SCOPED_EXPIRED_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'auth_v3_token_revoked.pkiz')) as f:
            self.REVOKED_v3_TOKEN_PKIZ = cms.cms_to_token(f.read())
        with open(os.path.join(CMSDIR, 'revocation_list.json')) as f:
            self.REVOCATION_LIST = jsonutils.loads(f.read())
        with open(os.path.join(CMSDIR, 'revocation_list.pem')) as f:
            self.SIGNED_REVOCATION_LIST = jsonutils.dumps({'signed': f.read()})

        self.SIGNING_CERT_FILE = os.path.join(CERTDIR, 'signing_cert.pem')
        with open(self.SIGNING_CERT_FILE) as f:
            self.SIGNING_CERT = f.read()

        self.KERBEROS_BIND = 'USER@REALM'

        self.SIGNING_KEY_FILE = os.path.join(KEYDIR, 'signing_key.pem')
        with open(self.SIGNING_KEY_FILE) as f:
            self.SIGNING_KEY = f.read()

        self.SIGNING_CA_FILE = os.path.join(CERTDIR, 'cacert.pem')
        with open(self.SIGNING_CA_FILE) as f:
            self.SIGNING_CA = f.read()

        self.UUID_TOKEN_DEFAULT = "ec6c0710ec2f471498484c1b53ab4f9d"
        self.UUID_TOKEN_NO_SERVICE_CATALOG = '8286720fbe4941e69fa8241723bb02df'
        self.UUID_TOKEN_UNSCOPED = '731f903721c14827be7b2dc912af7776'
        self.UUID_TOKEN_BIND = '3fc54048ad64405c98225ce0897af7c5'
        self.UUID_TOKEN_UNKNOWN_BIND = '8885fdf4d42e4fb9879e6379fa1eaf48'
        self.VALID_DIABLO_TOKEN = 'b0cf19b55dbb4f20a6ee18e6c6cf1726'
        self.v3_UUID_TOKEN_DEFAULT = '5603457654b346fdbb93437bfe76f2f1'
        self.v3_UUID_TOKEN_UNSCOPED = 'd34835fdaec447e695a0a024d84f8d79'
        self.v3_UUID_TOKEN_DOMAIN_SCOPED = 'e8a7b63aaa4449f38f0c5c05c3581792'
        self.v3_UUID_TOKEN_BIND = '2f61f73e1c854cbb9534c487f9bd63c2'
        self.v3_UUID_TOKEN_UNKNOWN_BIND = '7ed9781b62cd4880b8d8c6788ab1d1e2'

        self.UUID_SERVICE_TOKEN_DEFAULT = 'fe4c0710ec2f492748596c1b53ab124'
        self.v3_UUID_SERVICE_TOKEN_DEFAULT = 'g431071bbc2f492748596c1b53cb229'

        revoked_token = self.REVOKED_TOKEN
        if isinstance(revoked_token, six.text_type):
            revoked_token = revoked_token.encode('utf-8')
        self.REVOKED_TOKEN_HASH = utils.hash_signed_token(revoked_token)
        self.REVOKED_TOKEN_HASH_SHA256 = utils.hash_signed_token(revoked_token,
                                                                 mode='sha256')
        self.REVOKED_TOKEN_LIST = (
            {'revoked': [{'id': self.REVOKED_TOKEN_HASH,
                          'expires': timeutils.utcnow()}]})
        self.REVOKED_TOKEN_LIST_JSON = jsonutils.dumps(self.REVOKED_TOKEN_LIST)

        revoked_v3_token = self.REVOKED_v3_TOKEN
        if isinstance(revoked_v3_token, six.text_type):
            revoked_v3_token = revoked_v3_token.encode('utf-8')
        self.REVOKED_v3_TOKEN_HASH = utils.hash_signed_token(revoked_v3_token)
        hash = utils.hash_signed_token(revoked_v3_token, mode='sha256')
        self.REVOKED_v3_TOKEN_HASH_SHA256 = hash
        self.REVOKED_v3_TOKEN_LIST = (
            {'revoked': [{'id': self.REVOKED_v3_TOKEN_HASH,
                          'expires': timeutils.utcnow()}]})
        self.REVOKED_v3_TOKEN_LIST_JSON = jsonutils.dumps(
            self.REVOKED_v3_TOKEN_LIST)

        revoked_token_pkiz = self.REVOKED_TOKEN_PKIZ
        if isinstance(revoked_token_pkiz, six.text_type):
            revoked_token_pkiz = revoked_token_pkiz.encode('utf-8')
        self.REVOKED_TOKEN_PKIZ_HASH = utils.hash_signed_token(
            revoked_token_pkiz)
        revoked_v3_token_pkiz = self.REVOKED_v3_TOKEN_PKIZ
        if isinstance(revoked_v3_token_pkiz, six.text_type):
            revoked_v3_token_pkiz = revoked_v3_token_pkiz.encode('utf-8')
        self.REVOKED_v3_PKIZ_TOKEN_HASH = utils.hash_signed_token(
            revoked_v3_token_pkiz)

        self.REVOKED_TOKEN_PKIZ_LIST = (
            {'revoked': [{'id': self.REVOKED_TOKEN_PKIZ_HASH,
                          'expires': timeutils.utcnow()},
                         {'id': self.REVOKED_v3_PKIZ_TOKEN_HASH,
                          'expires': timeutils.utcnow()},
                         ]})
        self.REVOKED_TOKEN_PKIZ_LIST_JSON = jsonutils.dumps(
            self.REVOKED_TOKEN_PKIZ_LIST)

        self.SIGNED_TOKEN_SCOPED_KEY = cms.cms_hash_token(
            self.SIGNED_TOKEN_SCOPED)
        self.SIGNED_TOKEN_UNSCOPED_KEY = cms.cms_hash_token(
            self.SIGNED_TOKEN_UNSCOPED)
        self.SIGNED_v3_TOKEN_SCOPED_KEY = cms.cms_hash_token(
            self.SIGNED_v3_TOKEN_SCOPED)

        self.SIGNED_TOKEN_SCOPED_PKIZ_KEY = cms.cms_hash_token(
            self.SIGNED_TOKEN_SCOPED_PKIZ)
        self.SIGNED_TOKEN_UNSCOPED_PKIZ_KEY = cms.cms_hash_token(
            self.SIGNED_TOKEN_UNSCOPED_PKIZ)
        self.SIGNED_v3_TOKEN_SCOPED_PKIZ_KEY = cms.cms_hash_token(
            self.SIGNED_v3_TOKEN_SCOPED_PKIZ)

        self.INVALID_SIGNED_TOKEN = (
            "MIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "2222222222222222222222222222222222222222222222222222222222222222"
            "3333333333333333333333333333333333333333333333333333333333333333"
            "4444444444444444444444444444444444444444444444444444444444444444"
            "5555555555555555555555555555555555555555555555555555555555555555"
            "6666666666666666666666666666666666666666666666666666666666666666"
            "7777777777777777777777777777777777777777777777777777777777777777"
            "8888888888888888888888888888888888888888888888888888888888888888"
            "9999999999999999999999999999999999999999999999999999999999999999"
            "0000000000000000000000000000000000000000000000000000000000000000")

        self.INVALID_SIGNED_PKIZ_TOKEN = (
            "PKIZ_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "2222222222222222222222222222222222222222222222222222222222222222"
            "3333333333333333333333333333333333333333333333333333333333333333"
            "4444444444444444444444444444444444444444444444444444444444444444"
            "5555555555555555555555555555555555555555555555555555555555555555"
            "6666666666666666666666666666666666666666666666666666666666666666"
            "7777777777777777777777777777777777777777777777777777777777777777"
            "8888888888888888888888888888888888888888888888888888888888888888"
            "9999999999999999999999999999999999999999999999999999999999999999"
            "0000000000000000000000000000000000000000000000000000000000000000")

        # JSON responses keyed by token ID
        self.TOKEN_RESPONSES = {}

        # basic values
        PROJECT_ID = 'tenant_id1'
        PROJECT_NAME = 'tenant_name1'
        USER_ID = 'user_id1'
        USER_NAME = 'user_name1'
        DOMAIN_ID = 'domain_id1'
        DOMAIN_NAME = 'domain_name1'
        ROLE_NAME1 = 'role1'
        ROLE_NAME2 = 'role2'

        SERVICE_PROJECT_ID = 'service_project_id1'
        SERVICE_PROJECT_NAME = 'service_project_name1'
        SERVICE_USER_ID = 'service_user_id1'
        SERVICE_USER_NAME = 'service_user_name1'
        SERVICE_DOMAIN_ID = 'service_domain_id1'
        SERVICE_DOMAIN_NAME = 'service_domain_name1'
        SERVICE_ROLE_NAME1 = 'service_role1'
        SERVICE_ROLE_NAME2 = 'service_role2'

        self.SERVICE_TYPE = 'identity'
        self.UNVERSIONED_SERVICE_URL = 'http://keystone.server:5000/'
        self.SERVICE_URL = self.UNVERSIONED_SERVICE_URL + 'v2.0'

        # Old Tokens

        self.TOKEN_RESPONSES[self.VALID_DIABLO_TOKEN] = {
            'access': {
                'token': {
                    'id': self.VALID_DIABLO_TOKEN,
                    'expires': '2020-01-01T00:00:10.000123Z',
                    'tenantId': PROJECT_ID,
                },
                'user': {
                    'id': USER_ID,
                    'name': USER_NAME,
                    'roles': [
                        {'name': ROLE_NAME1},
                        {'name': ROLE_NAME2},
                    ],
                },
            },
        }

        # Generated V2 Tokens

        token = fixture.V2Token(token_id=self.UUID_TOKEN_DEFAULT,
                                tenant_id=PROJECT_ID,
                                tenant_name=PROJECT_NAME,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        token.add_role(name=ROLE_NAME1)
        token.add_role(name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint(public=self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.UUID_TOKEN_DEFAULT] = token

        token = fixture.V2Token(token_id=self.UUID_TOKEN_UNSCOPED,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        self.TOKEN_RESPONSES[self.UUID_TOKEN_UNSCOPED] = token

        token = fixture.V2Token(token_id='valid-token',
                                tenant_id=PROJECT_ID,
                                tenant_name=PROJECT_NAME,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        token.add_role(ROLE_NAME1)
        token.add_role(ROLE_NAME2)
        self.TOKEN_RESPONSES[self.UUID_TOKEN_NO_SERVICE_CATALOG] = token

        token = fixture.V2Token(token_id=self.SIGNED_TOKEN_SCOPED_KEY,
                                tenant_id=PROJECT_ID,
                                tenant_name=PROJECT_NAME,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        token.add_role(ROLE_NAME1)
        token.add_role(ROLE_NAME2)
        self.TOKEN_RESPONSES[self.SIGNED_TOKEN_SCOPED_KEY] = token

        token = fixture.V2Token(token_id=self.SIGNED_TOKEN_UNSCOPED_KEY,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        self.TOKEN_RESPONSES[self.SIGNED_TOKEN_UNSCOPED_KEY] = token

        token = fixture.V2Token(token_id=self.UUID_TOKEN_BIND,
                                tenant_id=PROJECT_ID,
                                tenant_name=PROJECT_NAME,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        token.add_role(ROLE_NAME1)
        token.add_role(ROLE_NAME2)
        token['access']['token']['bind'] = {'kerberos': self.KERBEROS_BIND}
        self.TOKEN_RESPONSES[self.UUID_TOKEN_BIND] = token

        token = fixture.V2Token(token_id=self.UUID_TOKEN_UNKNOWN_BIND,
                                tenant_id=PROJECT_ID,
                                tenant_name=PROJECT_NAME,
                                user_id=USER_ID,
                                user_name=USER_NAME)
        token.add_role(ROLE_NAME1)
        token.add_role(ROLE_NAME2)
        token['access']['token']['bind'] = {'FOO': 'BAR'}
        self.TOKEN_RESPONSES[self.UUID_TOKEN_UNKNOWN_BIND] = token

        token = fixture.V2Token(token_id=self.UUID_SERVICE_TOKEN_DEFAULT,
                                tenant_id=SERVICE_PROJECT_ID,
                                tenant_name=SERVICE_PROJECT_NAME,
                                user_id=SERVICE_USER_ID,
                                user_name=SERVICE_USER_NAME)
        token.add_role(name=SERVICE_ROLE_NAME1)
        token.add_role(name=SERVICE_ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint(public=self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.UUID_SERVICE_TOKEN_DEFAULT] = token

        # Generated V3 Tokens

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME,
                                project_id=PROJECT_ID,
                                project_name=PROJECT_NAME,
                                project_domain_id=DOMAIN_ID,
                                project_domain_name=DOMAIN_NAME)
        token.add_role(id=ROLE_NAME1, name=ROLE_NAME1)
        token.add_role(id=ROLE_NAME2, name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.v3_UUID_TOKEN_DEFAULT] = token

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME)
        self.TOKEN_RESPONSES[self.v3_UUID_TOKEN_UNSCOPED] = token

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME,
                                domain_id=DOMAIN_ID,
                                domain_name=DOMAIN_NAME)
        token.add_role(id=ROLE_NAME1, name=ROLE_NAME1)
        token.add_role(id=ROLE_NAME2, name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.v3_UUID_TOKEN_DOMAIN_SCOPED] = token

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME,
                                project_id=PROJECT_ID,
                                project_name=PROJECT_NAME,
                                project_domain_id=DOMAIN_ID,
                                project_domain_name=DOMAIN_NAME)
        token.add_role(name=ROLE_NAME1)
        token.add_role(name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.SIGNED_v3_TOKEN_SCOPED_KEY] = token

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME,
                                project_id=PROJECT_ID,
                                project_name=PROJECT_NAME,
                                project_domain_id=DOMAIN_ID,
                                project_domain_name=DOMAIN_NAME)
        token.add_role(name=ROLE_NAME1)
        token.add_role(name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        token['token']['bind'] = {'kerberos': self.KERBEROS_BIND}
        self.TOKEN_RESPONSES[self.v3_UUID_TOKEN_BIND] = token

        token = fixture.V3Token(user_id=USER_ID,
                                user_name=USER_NAME,
                                user_domain_id=DOMAIN_ID,
                                user_domain_name=DOMAIN_NAME,
                                project_id=PROJECT_ID,
                                project_name=PROJECT_NAME,
                                project_domain_id=DOMAIN_ID,
                                project_domain_name=DOMAIN_NAME)
        token.add_role(name=ROLE_NAME1)
        token.add_role(name=ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        token['token']['bind'] = {'FOO': 'BAR'}
        self.TOKEN_RESPONSES[self.v3_UUID_TOKEN_UNKNOWN_BIND] = token

        token = fixture.V3Token(user_id=SERVICE_USER_ID,
                                user_name=SERVICE_USER_NAME,
                                user_domain_id=SERVICE_DOMAIN_ID,
                                user_domain_name=SERVICE_DOMAIN_NAME,
                                project_id=SERVICE_PROJECT_ID,
                                project_name=SERVICE_PROJECT_NAME,
                                project_domain_id=SERVICE_DOMAIN_ID,
                                project_domain_name=SERVICE_DOMAIN_NAME)
        token.add_role(id=SERVICE_ROLE_NAME1,
                       name=SERVICE_ROLE_NAME1)
        token.add_role(id=SERVICE_ROLE_NAME2,
                       name=SERVICE_ROLE_NAME2)
        svc = token.add_service(self.SERVICE_TYPE)
        svc.add_endpoint('public', self.SERVICE_URL)
        self.TOKEN_RESPONSES[self.v3_UUID_SERVICE_TOKEN_DEFAULT] = token

        # PKIZ tokens generally link to above tokens

        self.TOKEN_RESPONSES[self.SIGNED_TOKEN_SCOPED_PKIZ_KEY] = (
            self.TOKEN_RESPONSES[self.SIGNED_TOKEN_SCOPED_KEY])
        self.TOKEN_RESPONSES[self.SIGNED_TOKEN_UNSCOPED_PKIZ_KEY] = (
            self.TOKEN_RESPONSES[self.SIGNED_TOKEN_UNSCOPED_KEY])
        self.TOKEN_RESPONSES[self.SIGNED_v3_TOKEN_SCOPED_PKIZ_KEY] = (
            self.TOKEN_RESPONSES[self.SIGNED_v3_TOKEN_SCOPED_KEY])

        self.JSON_TOKEN_RESPONSES = dict([(k, jsonutils.dumps(v)) for k, v in
                                          six.iteritems(self.TOKEN_RESPONSES)])


EXAMPLES_RESOURCE = testresources.FixtureResource(Examples())
