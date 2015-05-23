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

import fixtures
from oslo_config import fixture as cfg_fixture
from requests_mock.contrib import fixture as rm_fixture
import six
import testtools
import webob.dec

from keystonemiddleware import auth_token


class BaseAuthTokenTestCase(testtools.TestCase):

    def setUp(self):
        super(BaseAuthTokenTestCase, self).setUp()
        self.requests_mock = self.useFixture(rm_fixture.Fixture())
        self.logger = fixtures.FakeLogger(level=logging.DEBUG)
        self.cfg = self.useFixture(cfg_fixture.Config())

    @classmethod
    def create_middleware(cls, cb, conf=None):

        @webob.dec.wsgify
        def _do_cb(req):
            return cb(req)

        return auth_token.AuthProtocol(_do_cb, conf or {})

    @classmethod
    def create_simple_middleware(cls,
                                 status='200 OK',
                                 body='',
                                 headers=None,
                                 conf=None):
        def cb(req):
            resp = webob.Response(body, status)
            resp.headers.update(headers or {})
            return resp

        return cls.create_middleware(cb, conf)

    @classmethod
    def call(cls, middleware, method='GET', path='/', headers=None):
        req = webob.Request.blank(path)
        req.method = method

        for k, v in six.iteritems(headers or {}):
            req.headers[k] = v

        resp = req.get_response(middleware)
        resp.request = req
        return resp
