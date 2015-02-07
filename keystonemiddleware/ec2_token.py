# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
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

"""
Starting point for routing EC2 requests.

"""

from oslo_config import cfg
from oslo_serialization import jsonutils
import requests
import webob.dec
import webob.exc

keystone_ec2_opts = [
    cfg.StrOpt('url',
               default='http://localhost:5000/v2.0/ec2tokens',
               help='URL to get token from ec2 request.'),
    cfg.StrOpt('keyfile',
               help='Required if EC2 server requires client certificate.'),
    cfg.StrOpt('certfile',
               help='Client certificate key filename. Required if EC2 server '
                    'requires client certificate.'),
    cfg.StrOpt('cafile',
               help='A PEM encoded certificate authority to use when '
                    'verifying HTTPS connections. Defaults to the system '
                    'CAs.'),
    cfg.BoolOpt('insecure', default=False,
                help='Disable SSL certificate verification.'),
]

CONF = cfg.CONF
CONF.register_opts(keystone_ec2_opts, group='keystone_ec2_token')


class EC2Token(object):
    """Authenticate an EC2 request with keystone and convert to token."""

    def __init__(self, application):
        super(EC2Token, self).__init__()
        self._application = application

    @webob.dec.wsgify()
    def __call__(self, req):
        # Read request signature and access id.
        try:
            signature = req.params['Signature']
            access = req.params['AWSAccessKeyId']
        except KeyError:
            raise webob.exc.HTTPBadRequest()

        # Make a copy of args for authentication and signature verification.
        auth_params = dict(req.params)
        # Not part of authentication args
        auth_params.pop('Signature')

        # Authenticate the request.
        creds = {
            'ec2Credentials': {
                'access': access,
                'signature': signature,
                'host': req.host,
                'verb': req.method,
                'path': req.path,
                'params': auth_params,
            }
        }
        creds_json = jsonutils.dumps(creds)
        headers = {'Content-Type': 'application/json'}

        verify = True
        if CONF.keystone_ec2_token.insecure:
            verify = False
        elif CONF.keystone_ec2_token.cafile:
            verify = CONF.keystone_ec2_token.cafile

        cert = None
        if (CONF.keystone_ec2_token.certfile and
                CONF.keystone_ec2_token.keyfile):
            cert = (CONF.keystone_ec2_certfile,
                    CONF.keystone_ec2_token.keyfile)
        elif CONF.keystone_ec2_token.certfile:
            cert = CONF.keystone_ec2_token.certfile

        response = requests.post(CONF.keystone_ec2_token.url, data=creds_json,
                                 headers=headers, verify=verify, cert=cert)

        # NOTE(vish): We could save a call to keystone by
        #             having keystone return token, tenant,
        #             user, and roles from this call.

        result = response.json()
        try:
            token_id = result['access']['token']['id']
        except (AttributeError, KeyError):
            raise webob.exc.HTTPBadRequest()

        # Authenticated!
        req.headers['X-Auth-Token'] = token_id
        return self._application


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return EC2Token(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return EC2Token(None, conf)
