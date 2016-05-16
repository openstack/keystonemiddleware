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

import ast
import collections
import functools
import logging
import os.path
import re
import sys

from oslo_config import cfg
from oslo_context import context as oslo_context
try:
    import oslo_messaging
    messaging = True
except ImportError:
    messaging = False
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import credential
from pycadf import endpoint
from pycadf import eventfactory as factory
from pycadf import host
from pycadf import identifier
from pycadf import reason
from pycadf import reporterstep
from pycadf import resource
from pycadf import tag
from pycadf import timestamp
import six
from six.moves import configparser
from six.moves.urllib import parse as urlparse
import webob.dec

from keystonemiddleware.i18n import _LE, _LI


_LOG = None

_AUDIT_OPTS = [
    cfg.StrOpt('driver',
               default=None,
               help='The Driver to handle sending notifications. Possible '
                    'values are messaging, messagingv2, routing, log, test, '
                    'noop. If not specified, then value from '
                    'oslo_messaging_notifications conf section is used.'),
    cfg.ListOpt('topics',
                default=None,
                help='List of AMQP topics used for OpenStack notifications. If'
                     ' not specified, then value from '
                     ' oslo_messaging_notifications conf section is used.'),
    cfg.StrOpt('transport_url',
               default=None,
               secret=True,
               help='A URL representing messaging driver to use for '
                    'notification. If not specified, we fall back to the same '
                    'configuration used for RPC.'),
]
cfg.CONF.register_opts(_AUDIT_OPTS, group="audit_middleware_notifications")


def _log_and_ignore_error(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            _LOG.exception(_LE('An exception occurred processing '
                               'the API call: %s '), e)
    return wrapper


Service = collections.namedtuple('Service',
                                 ['id', 'name', 'type', 'admin_endp',
                                  'public_endp', 'private_endp'])


AuditMap = collections.namedtuple('AuditMap',
                                  ['path_kw',
                                   'custom_actions',
                                   'service_endpoints',
                                   'default_target_endpoint_type'])


# NOTE(blk-u): Compatibility for Python 2. SafeConfigParser and
# SafeConfigParser.readfp are deprecated in Python 3. Remove this when we drop
# support for Python 2.
if six.PY2:
    class _ConfigParser(configparser.SafeConfigParser):
        read_file = configparser.SafeConfigParser.readfp
else:
    _ConfigParser = configparser.ConfigParser


class OpenStackAuditApi(object):

    def __init__(self, cfg_file):
        """Configure to recognize and map known api paths."""
        path_kw = {}
        custom_actions = {}
        endpoints = {}
        default_target_endpoint_type = None

        if cfg_file:
            try:
                map_conf = _ConfigParser()
                map_conf.read_file(open(cfg_file))

                try:
                    default_target_endpoint_type = map_conf.get(
                        'DEFAULT', 'target_endpoint_type')
                except configparser.NoOptionError:  # nosec
                    # Ignore the undefined config option,
                    # default_target_endpoint_type remains None which is valid.
                    pass

                try:
                    custom_actions = dict(map_conf.items('custom_actions'))
                except configparser.Error:  # nosec
                    # custom_actions remains {} which is valid.
                    pass

                try:
                    path_kw = dict(map_conf.items('path_keywords'))
                except configparser.Error:  # nosec
                    # path_kw remains {} which is valid.
                    pass

                try:
                    endpoints = dict(map_conf.items('service_endpoints'))
                except configparser.Error:  # nosec
                    # endpoints remains {} which is valid.
                    pass
            except configparser.ParsingError as err:
                raise PycadfAuditApiConfigError(
                    'Error parsing audit map file: %s' % err)
        self._MAP = AuditMap(
            path_kw=path_kw, custom_actions=custom_actions,
            service_endpoints=endpoints,
            default_target_endpoint_type=default_target_endpoint_type)

    @staticmethod
    def _clean_path(value):
        """Clean path if path has json suffix."""
        return value[:-5] if value.endswith('.json') else value

    def get_action(self, req):
        """Take a given Request, parse url path to calculate action type.

        Depending on req.method:

        if POST:

        - path ends with 'action', read the body and use as action;
        - path ends with known custom_action, take action from config;
        - request ends with known path, assume is create action;
        - request ends with unknown path, assume is update action.

        if GET:

        - request ends with known path, assume is list action;
        - request ends with unknown path, assume is read action.

        if PUT, assume update action.
        if DELETE, assume delete action.
        if HEAD, assume read action.

        """
        path = req.path[:-1] if req.path.endswith('/') else req.path
        url_ending = self._clean_path(path[path.rfind('/') + 1:])
        method = req.method

        if url_ending + '/' + method.lower() in self._MAP.custom_actions:
            action = self._MAP.custom_actions[url_ending + '/' +
                                              method.lower()]
        elif url_ending in self._MAP.custom_actions:
            action = self._MAP.custom_actions[url_ending]
        elif method == 'POST':
            if url_ending == 'action':
                try:
                    if req.json:
                        body_action = list(req.json.keys())[0]
                        action = taxonomy.ACTION_UPDATE + '/' + body_action
                    else:
                        action = taxonomy.ACTION_CREATE
                except ValueError:
                    action = taxonomy.ACTION_CREATE
            elif url_ending not in self._MAP.path_kw:
                action = taxonomy.ACTION_UPDATE
            else:
                action = taxonomy.ACTION_CREATE
        elif method == 'GET':
            if url_ending in self._MAP.path_kw:
                action = taxonomy.ACTION_LIST
            else:
                action = taxonomy.ACTION_READ
        elif method == 'PUT' or method == 'PATCH':
            action = taxonomy.ACTION_UPDATE
        elif method == 'DELETE':
            action = taxonomy.ACTION_DELETE
        elif method == 'HEAD':
            action = taxonomy.ACTION_READ
        else:
            action = taxonomy.UNKNOWN

        return action

    def _get_service_info(self, endp):
        service = Service(
            type=self._MAP.service_endpoints.get(
                endp['type'],
                taxonomy.UNKNOWN),
            name=endp['name'],
            id=endp['endpoints'][0].get('id', endp['name']),
            admin_endp=endpoint.Endpoint(
                name='admin',
                url=endp['endpoints'][0].get('adminURL', taxonomy.UNKNOWN)),
            private_endp=endpoint.Endpoint(
                name='private',
                url=endp['endpoints'][0].get('internalURL', taxonomy.UNKNOWN)),
            public_endp=endpoint.Endpoint(
                name='public',
                url=endp['endpoints'][0].get('publicURL', taxonomy.UNKNOWN)))

        return service

    def _build_typeURI(self, req, service_type):
        """Build typeURI of target.

        Combines service type and corresponding path for greater detail.
        """
        type_uri = ''
        prev_key = None
        for key in re.split('/', req.path):
            key = self._clean_path(key)
            if key in self._MAP.path_kw:
                type_uri += '/' + key
            elif prev_key in self._MAP.path_kw:
                type_uri += '/' + self._MAP.path_kw[prev_key]
            prev_key = key
        return service_type + type_uri

    def _build_target(self, req, service):
        """Build target resource."""
        target_typeURI = (
            self._build_typeURI(req, service.type)
            if service.type != taxonomy.UNKNOWN else service.type)
        target = resource.Resource(typeURI=target_typeURI,
                                   id=service.id, name=service.name)
        if service.admin_endp:
            target.add_address(service.admin_endp)
        if service.private_endp:
            target.add_address(service.private_endp)
        if service.public_endp:
            target.add_address(service.public_endp)
        return target

    def get_target_resource(self, req):
        """Retrieve target information.

        If discovery is enabled, target will attempt to retrieve information
        from service catalog. If not, the information will be taken from
        given config file.
        """
        service_info = Service(type=taxonomy.UNKNOWN, name=taxonomy.UNKNOWN,
                               id=taxonomy.UNKNOWN, admin_endp=None,
                               private_endp=None, public_endp=None)
        try:
            catalog = ast.literal_eval(
                req.environ['HTTP_X_SERVICE_CATALOG'])
        except KeyError:
            raise PycadfAuditApiConfigError(
                'Service catalog is missing. '
                'Cannot discover target information')

        default_endpoint = None
        for endp in catalog:
            endpoint_urls = endp['endpoints'][0]
            admin_urlparse = urlparse.urlparse(
                endpoint_urls.get('adminURL', ''))
            public_urlparse = urlparse.urlparse(
                endpoint_urls.get('publicURL', ''))
            req_url = urlparse.urlparse(req.host_url)
            if (req_url.netloc == admin_urlparse.netloc
                    or req_url.netloc == public_urlparse.netloc):
                service_info = self._get_service_info(endp)
                break
            elif (self._MAP.default_target_endpoint_type and
                  endp['type'] == self._MAP.default_target_endpoint_type):
                default_endpoint = endp
        else:
            if default_endpoint:
                service_info = self._get_service_info(default_endpoint)
        return self._build_target(req, service_info)


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


class PycadfAuditApiConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class AuditMiddleware(object):
    """Create an audit event based on request/response.

    The audit middleware takes in various configuration options such as the
    ability to skip audit of certain requests. The full list of options can
    be discovered here:
    http://docs.openstack.org/developer/keystonemiddleware/audit.html
    """

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
        self._application = app
        global _LOG
        _LOG = logging.getLogger(conf.get('log_name', __name__))
        self._service_name = conf.get('service_name')
        self._ignore_req_list = [x.upper().strip() for x in
                                 conf.get('ignore_req_list', '').split(',')]
        self._cadf_audit = OpenStackAuditApi(conf.get('audit_map_file'))

        transport_aliases = self._get_aliases(cfg.CONF.project)
        if messaging:
            transport = oslo_messaging.get_transport(
                cfg.CONF,
                url=cfg.CONF.audit_middleware_notifications.transport_url,
                aliases=transport_aliases)
            self._notifier = oslo_messaging.Notifier(
                transport,
                os.path.basename(sys.argv[0]),
                driver=cfg.CONF.audit_middleware_notifications.driver,
                topics=cfg.CONF.audit_middleware_notifications.topics)

    def _emit_audit(self, context, event_type, payload):
        """Emit audit notification.

        if oslo.messaging enabled, send notification. if not, log event.
        """
        if messaging:
            self._notifier.info(context, event_type, payload)
        else:
            _LOG.info(_LI('Event type: %(event_type)s, Context: %(context)s, '
                          'Payload: %(payload)s'), {'context': context,
                                                    'event_type': event_type,
                                                    'payload': payload})

    def _create_event(self, req):
        correlation_id = identifier.generate_uuid()
        action = self._cadf_audit.get_action(req)

        initiator = ClientResource(
            typeURI=taxonomy.ACCOUNT_USER,
            id=req.environ['HTTP_X_USER_ID'],
            name=req.environ['HTTP_X_USER_NAME'],
            host=host.Host(address=req.client_addr, agent=req.user_agent),
            credential=KeystoneCredential(
                token=req.environ['HTTP_X_AUTH_TOKEN'],
                identity_status=req.environ['HTTP_X_IDENTITY_STATUS']),
            project_id=req.environ['HTTP_X_PROJECT_ID'])
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
        event = self._create_event(request)

        self._emit_audit(request.context, 'audit.http.request',
                         event.as_dict())

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

        self._emit_audit(request.context, 'audit.http.response',
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


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def audit_filter(app):
        return AuditMiddleware(app, **conf)
    return audit_filter
