#! /usr/bin/python3

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

def add_ospf(params):
    """Change /etc/dhcp/dhcpd.conf config file.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    cmd_list = []

    # routerId
    routerId = params.get('routerId')
    if routerId:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   =  "add routerId %s to OSPF" % routerId
        cmd['cmd']['params']  = [
            'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "ospf router-id %s"; sudo /usr/bin/vtysh -c "write"' % routerId ]
        cmd['revert'] = {}
        cmd['revert']['name']    = "exec"
        cmd['revert']['descr']   =  "remove routerId %s from OSPF" % routerId
        cmd['revert']['params']  = [
            'sudo /usr/bin/vtysh -c "configure" -c "router ospf" -c "no ospf router-id %s"; sudo /usr/bin/vtysh -c "write"' % routerId ]
        cmd_list.append(cmd)
    return cmd_list

def get_request_key(params):
    """Get add-dhcp-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-dhcp-config command.
    """
    key = 'add-ospf-config'
    return key
