#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Build open standard audit information based on incoming requests

AuditMiddleware filter should be placed after keystonemiddleware.auth_token
in the pipeline so that it can utilise the information the Identity server
provides.
"""

import functools
import logging
import os.path
import sys

from oslo.config import cfg
try:
    import oslo.messaging
    messaging = True
except ImportError:
    messaging = False
import pycadf
from pycadf.audit import api
import webob.dec

from keystonemiddleware.i18n import _LE, _LI
from keystonemiddleware.openstack.common import context


LOG = None


def log_and_ignore_error(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            LOG.exception(_LE('An exception occurred processing '
                              'the API call: %s '), e)
    return wrapper


class AuditMiddleware(object):
    """Create an audit event based on request/response."""

    @staticmethod
    def _get_aliases(proj):
        aliases = {}
        if proj:
            # Aliases to support backward compatibility
            aliases = {
                '%s.openstack.common.rpc.impl_kombu' % proj: 'rabbit',
                '%s.openstack.common.rpc.impl_qpid' % proj: 'qpid',
                '%s.openstack.common.rpc.impl_zmq' % proj: 'zmq',
                '%s.rpc.impl_kombu' % proj: 'rabbit',
                '%s.rpc.impl_qpid' % proj: 'qpid',
                '%s.rpc.impl_zmq' % proj: 'zmq',
            }
        return aliases

    def __init__(self, app, **conf):
        self.application = app
        global LOG
        LOG = logging.getLogger(conf.get('log_name', __name__))
        self.service_name = conf.get('service_name')
        self.ignore_req_list = [x.upper().strip() for x in
                                conf.get('ignore_req_list', '').split(',')]
        self.cadf_audit = api.OpenStackAuditApi(
            conf.get('audit_map_file'))

        transport_aliases = AuditMiddleware._get_aliases(cfg.CONF.project)
        if messaging:
            self.notifier = oslo.messaging.Notifier(
                oslo.messaging.get_transport(cfg.CONF,
                                             aliases=transport_aliases),
                os.path.basename(sys.argv[0]))

    def _emit_audit(self, context, event_type, payload):
        """Emit audit notification

        if oslo.messaging enabled, send notification. if not, log event.
        """

        if messaging:
            self.notifier.info(context, event_type, payload)
        else:
            LOG.info(_LI('Event type: %(event_type)s, Context: %(context)s, '
                         'Payload: %(payload)s'), {'context': context,
                                                   'event_type': event_type,
                                                   'payload': payload})

    @log_and_ignore_error
    def process_request(self, request):
        correlation_id = pycadf.identifier.generate_uuid()
        self.event = self.cadf_audit.create_event(request, correlation_id)

        self._emit_audit(context.get_admin_context().to_dict(),
                         'audit.http.request', self.event.as_dict())

    @log_and_ignore_error
    def process_response(self, request, response=None):
        if not hasattr(self, 'event'):
            # NOTE(gordc): handle case where error processing request
            correlation_id = pycadf.identifier.generate_uuid()
            self.event = self.cadf_audit.create_event(request, correlation_id)

        if response:
            if response.status_int >= 200 and response.status_int < 400:
                result = pycadf.cadftaxonomy.OUTCOME_SUCCESS
            else:
                result = pycadf.cadftaxonomy.OUTCOME_FAILURE
            self.event.reason = pycadf.reason.Reason(
                reasonType='HTTP', reasonCode=str(response.status_int))
        else:
            result = pycadf.cadftaxonomy.UNKNOWN

        self.event.outcome = result
        self.event.add_reporterstep(
            pycadf.reporterstep.Reporterstep(
                role=pycadf.cadftype.REPORTER_ROLE_MODIFIER,
                reporter=pycadf.resource.Resource(id='target'),
                reporterTime=pycadf.timestamp.get_utc_now()))

        self._emit_audit(context.get_admin_context().to_dict(),
                         'audit.http.response', self.event.as_dict())

    @webob.dec.wsgify
    def __call__(self, req):
        if req.method in self.ignore_req_list:
            return req.get_response(self.application)

        self.process_request(req)
        try:
            response = req.get_response(self.application)
        except Exception:
            self.process_response(req)
            raise
        else:
            self.process_response(req, response)
        return response


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def audit_filter(app):
        return AuditMiddleware(app, **conf)
    return audit_filter
