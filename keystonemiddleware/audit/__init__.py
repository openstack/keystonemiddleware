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
Build open standard audit information based on incoming requests.

AuditMiddleware filter should be placed after keystonemiddleware.auth_token
in the pipeline so that it can utilise the information the Identity server
provides.
"""

import copy
import functools
import logging

from oslo_config import cfg
from oslo_context import context as oslo_context
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import credential
from pycadf import eventfactory as factory
from pycadf import host
from pycadf import identifier
from pycadf import reason
from pycadf import reporterstep
from pycadf import resource
from pycadf import tag
from pycadf import timestamp
import webob.dec

from keystonemiddleware._common import config
from keystonemiddleware.audit import _api
from keystonemiddleware.audit import _notifier
from keystonemiddleware.i18n import _LE


_LOG = None
AUDIT_MIDDLEWARE_GROUP = 'audit_middleware_notifications'

_AUDIT_OPTS = [
    cfg.StrOpt('driver',
               help='The Driver to handle sending notifications. Possible '
                    'values are messaging, messagingv2, routing, log, test, '
                    'noop. If not specified, then value from '
                    'oslo_messaging_notifications conf section is used.'),
    cfg.ListOpt('topics',
                help='List of AMQP topics used for OpenStack notifications. If'
                     ' not specified, then value from '
                     ' oslo_messaging_notifications conf section is used.'),
    cfg.StrOpt('transport_url',
               secret=True,
               help='A URL representing messaging driver to use for '
                    'notification. If not specified, we fall back to the same '
                    'configuration used for RPC.'),
]
CONF = cfg.CONF
CONF.register_opts(_AUDIT_OPTS, group=AUDIT_MIDDLEWARE_GROUP)


def _log_and_ignore_error(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            _LOG.exception(_LE('An exception occurred processing '
                               'the API call: %s '), e)
    return wrapper


class ClientResource(resource.Resource):
    def __init__(self, project_id=None, **kwargs):
        super(ClientResource, self).__init__(**kwargs)
        if project_id is not None:
            self.project_id = project_id


class KeystoneCredential(credential.Credential):
    def __init__(self, identity_status=None, **kwargs):
        super(KeystoneCredential, self).__init__(**kwargs)
        if identity_status is not None:
            self.identity_status = identity_status


class AuditMiddleware(object):
    """Create an audit event based on request/response.

    The audit middleware takes in various configuration options such as the
    ability to skip audit of certain requests. The full list of options can
    be discovered here:
    http://docs.openstack.org/developer/keystonemiddleware/audit.html
    """

    def __init__(self, app, **conf):
        self._application = app
        self._conf = config.Config('audit',
                                   AUDIT_MIDDLEWARE_GROUP,
                                   _list_opts(),
                                   conf)
        global _LOG
        _LOG = logging.getLogger(conf.get('log_name', __name__))
        self._service_name = conf.get('service_name')
        self._ignore_req_list = [x.upper().strip() for x in
                                 conf.get('ignore_req_list', '').split(',')]
        self._cadf_audit = _api.OpenStackAuditApi(conf.get('audit_map_file'),
                                                  _LOG)
        self._notifier = _notifier.create_notifier(self._conf, _LOG)

    def _create_event(self, req):
        correlation_id = identifier.generate_uuid()
        action = self._cadf_audit.get_action(req)

        initiator = ClientResource(
            typeURI=taxonomy.ACCOUNT_USER,
            id=req.environ.get('HTTP_X_USER_ID', taxonomy.UNKNOWN),
            name=req.environ.get('HTTP_X_USER_NAME', taxonomy.UNKNOWN),
            host=host.Host(address=req.client_addr, agent=req.user_agent),
            credential=KeystoneCredential(
                token=req.environ.get('HTTP_X_AUTH_TOKEN', ''),
                identity_status=req.environ.get('HTTP_X_IDENTITY_STATUS',
                                                taxonomy.UNKNOWN)),
            project_id=req.environ.get('HTTP_X_PROJECT_ID', taxonomy.UNKNOWN))
        target = self._cadf_audit.get_target_resource(req)

        event = factory.EventFactory().new_event(
            eventType=cadftype.EVENTTYPE_ACTIVITY,
            outcome=taxonomy.OUTCOME_PENDING,
            action=action,
            initiator=initiator,
            target=target,
            observer=resource.Resource(id='target'))
        event.requestPath = req.path_qs
        event.add_tag(tag.generate_name_value_tag('correlation_id',
                                                  correlation_id))
        # cache model in request to allow tracking of transistive steps.
        req.environ['cadf_event'] = event
        return event

    @_log_and_ignore_error
    def _process_request(self, request):
        self._notifier.notify(request.context,
                              'audit.http.request',
                              self._create_event(request).as_dict())

    @_log_and_ignore_error
    def _process_response(self, request, response=None):
        # NOTE(gordc): handle case where error processing request
        if 'cadf_event' not in request.environ:
            self._create_event(request)
        event = request.environ['cadf_event']

        if response:
            if response.status_int >= 200 and response.status_int < 400:
                result = taxonomy.OUTCOME_SUCCESS
            else:
                result = taxonomy.OUTCOME_FAILURE
            event.reason = reason.Reason(
                reasonType='HTTP', reasonCode=str(response.status_int))
        else:
            result = taxonomy.UNKNOWN

        event.outcome = result
        event.add_reporterstep(
            reporterstep.Reporterstep(
                role=cadftype.REPORTER_ROLE_MODIFIER,
                reporter=resource.Resource(id='target'),
                reporterTime=timestamp.get_utc_now()))

        self._notifier.notify(request.context,
                              'audit.http.response',
                              event.as_dict())

    @webob.dec.wsgify
    def __call__(self, req):
        if req.method in self._ignore_req_list:
            return req.get_response(self._application)

        # Cannot use a RequestClass on wsgify above because the `req` object is
        # a `WebOb.Request` when this method is called so the RequestClass is
        # ignored by the wsgify wrapper.
        req.context = oslo_context.get_admin_context().to_dict()

        self._process_request(req)
        try:
            response = req.get_response(self._application)
        except Exception:
            self._process_response(req)
            raise
        else:
            self._process_response(req, response)
        return response


def _list_opts():
    """Return a list of oslo_config options available in audit middleware.

    The returned list includes all oslo_config options which may be registered
    at runtime by the project.

    Each element of the list is a tuple. The first element is the name of the
    group under which the list of elements in the second element will be
    registered. A group name of None corresponds to the [DEFAULT] group in
    config files.

    :returns: a list of (group_name, opts) tuples
    """
    return [(AUDIT_MIDDLEWARE_GROUP, copy.deepcopy(_AUDIT_OPTS))]


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def audit_filter(app):
        return AuditMiddleware(app, **conf)
    return audit_filter


# NOTE(jamielennox): Maintained here for public API compatibility.
Service = _api.Service
AuditMap = _api.AuditMap
PycadfAuditApiConfigError = _api.PycadfAuditApiConfigError
OpenStackAuditApi = _api.OpenStackAuditApi
