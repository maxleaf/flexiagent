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

def add_lte(params):
    """Generate commands to add DHCP configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'lte_connect',
                'args': { 'params': params }
    }
    cmd['cmd']['descr'] = "Connect LTE to the cellular provider"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'lte_disconnect',
                'args': { 'dev_id': params['dev_id'] }
    }
    cmd['revert']['descr'] = "Disconnect LTE from the cellular provider"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'configure_lte_interface',
                'args': { 'params': params }
    }
    cmd['cmd']['descr'] = "Configure LTE IP and gateway on linux interface if vpp is not run"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-lte-%s' % params['dev_id']
    return key
