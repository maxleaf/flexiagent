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

# This migration script adds defualt dns servers to interfaces.

import os
import sys

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

from fwrouter_cfg import FwRouterCfg

def _set_default_dns_servers():
    """
    """
    with FwRouterCfg("/etc/flexiwan/agent/.requests.sqlite") as router_cfg:
        wan_interfaces = router_cfg.get_interfaces(type='wan')

        for wan in wan_interfaces:
            dhcp = wan.get('dhcp')

            if not dhcp:
                continue

            # No need to update dns for dhcp interfaces since they received dns servers from dhcp server
            if dhcp == 'yes':
                continue

            if 'dnsServers' in wan and len(wan['dnsServers']) > 0:
                continue

            wan['dnsServers'] = ['8.8.8.8', '8.8.4.4']

            new_request = {
                'message':   'add-interface',
                'params':    wan
            }

            router_cfg.update(new_request, [], False)

def migrate(prev_version, new_version, upgrade):
    if upgrade != 'upgrade':
        return

    try:
        print("* Migrating dns servers...")
        _set_default_dns_servers()

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()