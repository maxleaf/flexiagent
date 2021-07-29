################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020 flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

# This migration script adds new fleximanage felids to tunnel creation.

import os
import re
import yaml
import sys
import subprocess

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwglobals
import fwutils

from fwrouter_cfg import FwRouterCfg
from fwrouter_api import fwrouter_translators

def _change_interface_identifier():
    """ The purpose of this migration is to change the existing interface identifiers to the new format.
    """
    with FwRouterCfg("/etc/flexiwan/agent/.requests.sqlite") as router_cfg:
        router_cfg.set_translators(fwrouter_translators)
        all_interfaces = router_cfg.get_interfaces()

        for intf in all_interfaces:
            if 'pci' in intf:
                req_key = 'add-interface:%s' % intf['pci']
                del router_cfg.db[req_key]

                intf['dev_id'] = fwutils.dev_id_add_type(intf['pci'])
                del intf['pci']

                new_request = {
                    'message':   'add-interface',
                    'params':    intf
                }

                router_cfg.update(new_request, [], False)

        dhcp_requests = router_cfg.dump(types=['add-dhcp-config'])
        for request in dhcp_requests:
            req_key = 'add-dhcp-config %s' % request['params']['interface']
            del router_cfg.db[req_key]

            request['params']['interface'] = fwutils.dev_id_add_type(request['params']['interface'])
            router_cfg.update(request, [], False)

        routes_requests = router_cfg.dump(types=['add-route'])
        for request in routes_requests:
            if 'pci' in request['params']:
                key = router_cfg._get_request_key(request)
                del router_cfg.db[key]

                request['params']['dev_id'] = fwutils.dev_id_add_type(request['params']['pci'])
                del request['params']['pci']
                router_cfg.update(request, [], False)

        tunnels_requests = router_cfg.dump(types=['add-tunnel'])
        for request in tunnels_requests:
            if 'pci' in request['params']:
                request['params']['dev_id'] = fwutils.dev_id_add_type(request['params']['pci'])
                del request['params']['pci']
                router_cfg.update(request, [], False)


def migrate(prev_version, new_version, upgrade):
    if upgrade != 'upgrade':
        return

    try:
        print("* Migrating pciaddr key to dev_id...")
        _change_interface_identifier()

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()