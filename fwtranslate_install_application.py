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
import ctypes
import os
import re
import time

import fwglobals
import fwtranslate_revert
import fwutils

# install-application
# --------------------------------------
# Translates request:
#
# {
#     "entity": "agent",
#     "message": "install-application",
#     "params": {
#         "id": "5edf9e2e4b53582cb4a713e8",
#         "name": "Open VPN",
#         "version": "1.2.3.5",
#         "routeAllOverVpn": true,
#         "remoteClientIp": "10.10.10.64/26",
#         "deviceWANIp": "192.168.1.53"
#     }
# },


def _generate_id(ret):
    """Generate identifier.

    :param ret:         Initial id value.

    :returns: identifier.
    """
    ret += 1
    if ret == 2 ** 32:  # sad_id is u32 in VPP
        ret = 0
    return ret


sa_index = 0


def _generate_application_id():
    """Generate application identifier.

    :returns: New application identifier.
    """
    global sa_index
    application_index = _generate_id(sa_index)
    return copy.deepcopy(application_index)


def reset_application_id():
    """Reset application identifier.
    """
    global sa_index
    sa_index = 0


def install_application(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    app_type = params['type']

    cmd_params = {}
    cmd_revert_params = {}
    cmd_params['module'] = 'fwutils'
    cmd_revert_params['module'] = 'fwutils'
        
    if (app_type == 'open-vpn'):
        cmd_params['func'] = 'install_openvpn_server'
        cmd_params['args'] = {
            'version': params['config']['version'],
            'routeAllOverVpn': params['config']['routeAllOverVpn'],
            'remoteClientIp': params['config']['remoteClientIp'],
            'deviceWANIp': params['config']['deviceWANIp'],
            'remove': False,
            'caKey': params['config']['caKey'],
            'caCrt': params['config']['caCrt'],
            'serverKey': params['config']['serverKey'],
            'serverCrt': params['config']['serverCrt'],
            'tlsKey': params['config']['tlsKey']
             # 'dhKey': params['dhKey']
        }

        cmd_revert_params['func'] = 'remove_openvpn_server'    

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "install application (name=%s)" % (params['name'])
    cmd['cmd']['params'] = cmd_params    

    cmd['revert'] = {}
    cmd['revert']['name'] = "python"
    cmd['revert']['descr'] = "remove application (name=%s)" % (params['name'])
    cmd['revert']['params'] = cmd_revert_params

    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return application key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'install-service-%s' % params['type']
