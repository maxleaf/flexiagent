#! /usr/bin/python

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

import copy
import os

import fwutils
import fwglobals

def _change_dhcpd_conf(params, cmd_list):
    """Change /etc/dhcp/dhcpd.conf config file.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    params['is_add'] = 1
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
        'module': 'fwutils',
        'func': 'modify_dhcpd',
        'args': {'params': params}
    }
    revert_params = copy.deepcopy(params)
    revert_params['is_add'] = 0
    cmd['cmd']['descr'] = "modify dhcpd config file"
    cmd['revert'] = {}
    cmd['revert']['name'] = 'python'
    cmd['revert']['params'] = {
        'module': 'fwutils',
        'func': 'modify_dhcpd',
        'args': {'params': revert_params}
    }
    cmd['revert']['descr'] = "clean dhcpd config file"

    cmd_list.append(cmd)


def _restart_dhcp_server(cmd_list):
    """Restart DHCP server.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "exec"
    cmd['cmd']['params'] = ["sudo systemctl restart isc-dhcp-server"]
    cmd['cmd']['descr'] = "restart dhcp service"
    cmd['revert'] = {}
    cmd['revert']['name'] = 'exec'
    cmd['revert']['params'] = ["sudo systemctl restart isc-dhcp-server"]
    cmd['revert']['descr'] = "restart dhcp service"
    cmd_list.append(cmd)


def add_dhcp_config(params):
    """Generate commands to add DHCP configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    _change_dhcpd_conf(params, cmd_list)
    _restart_dhcp_server(cmd_list)

    return cmd_list


def get_request_key(params):
    """Get add-dhcp-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-dhcp-config command.
    """
    key = 'add-dhcp-config %s' % params['interface']
    return key
