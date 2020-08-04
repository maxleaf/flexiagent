################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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

# This migration script fix the dhcp and metric configuration for device interfaces

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
import fwdb_requests
import fwutils

from fwdb_requests import FwDbRequests

SQLITE_DB_FILE = '/etc/flexiwan/agent/.requests.sqlite'


def _find_primary_ip():
    output = subprocess.check_output('ip route show default', shell=True).strip()
    routes = output.splitlines()
    if routes:
        route = routes[0]
        dev_split = route.split('dev ')
        dev = dev_split[1].split(' ')[0] if len(dev_split) > 1 else ''
        if dev:
            src = subprocess.check_output("ip -f inet address show %s | awk '/inet / {print $2}'" % dev,
                                          shell=True).strip()
            return src

    return ''


def _find_gateway_ip(pci):
    ip = ''
    ifname = fwutils.pci_to_linux_iface(pci)
    if ifname:
        ip, metric = fwutils.get_linux_interface_gateway(ifname)
        return ip

    if not ip:
        ip, dev = fwutils.get_default_route()
        return ip

    return ''


def migrate(prev_version, new_version, upgrade):
    try:
        print("* Migrating interface DHCP and Metrics configuration...")
        metric = 100
        primary_ip = _find_primary_ip()
        with FwDbRequests(SQLITE_DB_FILE) as db_requests:
            for key, request in db_requests.db.items():
                if re.match('add-interface', key):
                    if re.match('wan', request['params']['type'], re.IGNORECASE):
                        if not 'gateway' in request['params']:
                            gw_ip = _find_gateway_ip(request['params']['pci'])
                            request['params']['gateway'] = gw_ip

                        if not 'metric' in request['params']:
                            if not primary_ip:
                                primary_ip = request['params']['addr']
                            if primary_ip == request['params']['addr']:
                                request['params']['metric'] = str(0)
                            else:
                                request['params']['metric'] = str(metric)
                                metric += 1
                        db_requests.update(key, request['request'], request['params'], request['cmd_list'],
                                           request['executed'])

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()


