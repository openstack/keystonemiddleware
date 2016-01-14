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

import copy

from keystoneauth1 import loading

import keystonemiddleware.auth_token
from keystonemiddleware.auth_token import _base

auth_token_opts = [
    (_base.AUTHTOKEN_GROUP,
     keystonemiddleware.auth_token._OPTS +
     loading.get_auth_common_conf_options())
]

__all__ = (
    'list_opts',
)


def list_opts():
    """Return a list of oslo_config options available in auth_token middleware.

    The returned list includes the non-deprecated oslo_config options which may
    be registered at runtime by the project. The purpose of this is to allow
    tools like the Oslo sample config file generator to discover the options
    exposed to users by this middleware.

    Deprecated Options should not show up here so as to not be included in
    sample configuration.

    Each element of the list is a tuple. The first element is the name of the
    group under which the list of elements in the second element will be
    registered. A group name of None corresponds to the [DEFAULT] group in
    config files.

    This function is discoverable via the entry point
    'keystonemiddleware.auth_token' under the 'oslo.config.opts' namespace.

    :returns: a list of (group_name, opts) tuples
    """
    auth_token_opts = (keystonemiddleware.auth_token._OPTS +
                       loading.get_auth_common_conf_options())

    return [(_base.AUTHTOKEN_GROUP, copy.deepcopy(auth_token_opts))]
