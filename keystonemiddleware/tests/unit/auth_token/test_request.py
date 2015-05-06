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

import itertools
import uuid

from keystoneclient import access
from keystoneclient import fixture

from keystonemiddleware.auth_token import _request
from keystonemiddleware.tests.unit import utils


class RequestObjectTests(utils.TestCase):

    def setUp(self):
        super(RequestObjectTests, self).setUp()
        self.request = _request._AuthTokenRequest.blank('/')

    def test_setting_user_token_valid(self):
        self.assertNotIn('X-Identity-Status', self.request.headers)

        self.request.user_token_valid = True
        self.assertEqual('Confirmed',
                         self.request.headers['X-Identity-Status'])
        self.assertTrue(self.request.user_token_valid)

        self.request.user_token_valid = False
        self.assertEqual('Invalid',
                         self.request.headers['X-Identity-Status'])
        self.assertFalse(self.request.user_token_valid)

    def test_setting_service_token_valid(self):
        self.assertNotIn('X-Service-Identity-Status', self.request.headers)

        self.request.service_token_valid = True
        self.assertEqual('Confirmed',
                         self.request.headers['X-Service-Identity-Status'])
        self.assertTrue(self.request.service_token_valid)

        self.request.service_token_valid = False
        self.assertEqual('Invalid',
                         self.request.headers['X-Service-Identity-Status'])
        self.assertFalse(self.request.service_token_valid)

    def test_removing_headers(self):
        GOOD = ('X-Auth-Token',
                'unknownstring',
                uuid.uuid4().hex)

        BAD = ('X-Domain-Id',
               'X-Domain-Name',
               'X-Project-Id',
               'X-Project-Name',
               'X-Project-Domain-Id',
               'X-Project-Domain-Name',
               'X-User-Id',
               'X-User-Name',
               'X-User-Domain-Id',
               'X-User-Domain-Name',
               'X-Roles',
               'X-Identity-Status',

               'X-Service-Domain-Id',
               'X-Service-Domain-Name',
               'X-Service-Project-Id',
               'X-Service-Project-Name',
               'X-Service-Project-Domain-Id',
               'X-Service-Project-Domain-Name',
               'X-Service-User-Id',
               'X-Service-User-Name',
               'X-Service-User-Domain-Id',
               'X-Service-User-Domain-Name',
               'X-Service-Roles',
               'X-Service-Identity-Status',

               'X-Service-Catalog',

               'X-Role',
               'X-User',
               'X-Tenant-Id',
               'X-Tenant-Name',
               'X-Tenant',
               )

        header_vals = {}

        for header in itertools.chain(GOOD, BAD):
            v = uuid.uuid4().hex
            header_vals[header] = v
            self.request.headers[header] = v

        self.request.remove_auth_headers()

        for header in BAD:
            self.assertNotIn(header, self.request.headers)

        for header in GOOD:
            self.assertEqual(header_vals[header], self.request.headers[header])

    def _test_v3_headers(self, token, prefix):
        self.assertEqual(token.domain_id,
                         self.request.headers['X%s-Domain-Id' % prefix])
        self.assertEqual(token.domain_name,
                         self.request.headers['X%s-Domain-Name' % prefix])
        self.assertEqual(token.project_id,
                         self.request.headers['X%s-Project-Id' % prefix])
        self.assertEqual(token.project_name,
                         self.request.headers['X%s-Project-Name' % prefix])
        self.assertEqual(
            token.project_domain_id,
            self.request.headers['X%s-Project-Domain-Id' % prefix])
        self.assertEqual(
            token.project_domain_name,
            self.request.headers['X%s-Project-Domain-Name' % prefix])

        self.assertEqual(token.user_id,
                         self.request.headers['X%s-User-Id' % prefix])
        self.assertEqual(token.user_name,
                         self.request.headers['X%s-User-Name' % prefix])
        self.assertEqual(
            token.user_domain_id,
            self.request.headers['X%s-User-Domain-Id' % prefix])
        self.assertEqual(
            token.user_domain_name,
            self.request.headers['X%s-User-Domain-Name' % prefix])

    def test_project_scoped_user_headers(self):
        token = fixture.V3Token()
        token.set_project_scope()
        token_id = uuid.uuid4().hex

        auth_ref = access.AccessInfo.factory(token_id=token_id, body=token)
        self.request.set_user_headers(auth_ref, include_service_catalog=True)

        self._test_v3_headers(token, '')

    def test_project_scoped_service_headers(self):
        token = fixture.V3Token()
        token.set_project_scope()
        token_id = uuid.uuid4().hex

        auth_ref = access.AccessInfo.factory(token_id=token_id, body=token)
        self.request.set_service_headers(auth_ref)

        self._test_v3_headers(token, '-Service')


class CatalogConversionTests(utils.TestCase):

    PUBLIC_URL = 'http://server:5000/v2.0'
    ADMIN_URL = 'http://admin:35357/v2.0'
    INTERNAL_URL = 'http://internal:5000/v2.0'

    REGION_ONE = 'RegionOne'
    REGION_TWO = 'RegionTwo'
    REGION_THREE = 'RegionThree'

    def test_basic_convert(self):
        token = fixture.V3Token()
        s = token.add_service(type='identity')
        s.add_standard_endpoints(public=self.PUBLIC_URL,
                                 admin=self.ADMIN_URL,
                                 internal=self.INTERNAL_URL,
                                 region=self.REGION_ONE)

        auth_ref = access.AccessInfo.factory(body=token)
        catalog_data = auth_ref.service_catalog.get_data()
        catalog = _request._v3_to_v2_catalog(catalog_data)

        self.assertEqual(1, len(catalog))
        service = catalog[0]
        self.assertEqual(1, len(service['endpoints']))
        endpoints = service['endpoints'][0]

        self.assertEqual('identity', service['type'])
        self.assertEqual(4, len(endpoints))
        self.assertEqual(self.PUBLIC_URL, endpoints['publicURL'])
        self.assertEqual(self.ADMIN_URL, endpoints['adminURL'])
        self.assertEqual(self.INTERNAL_URL, endpoints['internalURL'])
        self.assertEqual(self.REGION_ONE, endpoints['region'])

    def test_multi_region(self):
        token = fixture.V3Token()
        s = token.add_service(type='identity')

        s.add_endpoint('internal', self.INTERNAL_URL, region=self.REGION_ONE)
        s.add_endpoint('public', self.PUBLIC_URL, region=self.REGION_TWO)
        s.add_endpoint('admin', self.ADMIN_URL, region=self.REGION_THREE)

        auth_ref = access.AccessInfo.factory(body=token)
        catalog_data = auth_ref.service_catalog.get_data()
        catalog = _request._v3_to_v2_catalog(catalog_data)

        self.assertEqual(1, len(catalog))
        service = catalog[0]

        # the 3 regions will come through as 3 separate endpoints
        expected = [{'internalURL': self.INTERNAL_URL,
                    'region': self.REGION_ONE},
                    {'publicURL': self.PUBLIC_URL,
                     'region': self.REGION_TWO},
                    {'adminURL': self.ADMIN_URL,
                     'region': self.REGION_THREE}]

        self.assertEqual('identity', service['type'])
        self.assertEqual(3, len(service['endpoints']))
        for e in expected:
            self.assertIn(e, expected)
