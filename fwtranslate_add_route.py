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

import os
import fwglobals
import fwtranslate_revert
import fwutils

# add_route
# --------------------------------------
# Translates request:
#
#    {
#       "message": "add-route",
#       "params": {
#           "addr":"10.0.0.4/24" (OR "10.0.0.4" OR "default")
#           "via":"192.168.1.1",
#           "dev_id":"0000:00:08.00"   (device, optional)
#       }
#    }
#
# into one of following commands:
#
#   ip route add default via 192.168.1.1 [dev <interface>]
#   ip route add 192.0.2.1 via 10.0.0.1 [dev <interface>]
#   ip route add 192.0.2.0/24 via 10.0.0.1 [dev <interface>]
#
#   On CentOS/Fedora/RH "systemctl restart network.service" is needed afterwards.
#
#
def add_route(params):
    """Generate commands to configure ip route in Linux and VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "ip route add %s via %s dev %s" % (params['addr'], params['via'], str(params.get('dev_id')))
    cmd['cmd']['params']    = {
                                'module': 'fwutils',
                                'func':   'add_remove_static_route',
                                'args':   {
                                    'addr'  : params['addr'],
                                    'via'   : params['via'],
                                    'metric': params.get('metric'),
                                    'remove': False,
                                    'dev_id': params.get('dev_id')
                                }
                              }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "ip route del %s via %s dev %s" % (params['addr'], params['via'], str(params.get('dev_id')))
    cmd['revert']['params'] = {
                                'module': 'fwutils',
                                'func':   'add_remove_static_route',
                                'args':   {
                                    'addr'  : params['addr'],
                                    'via'   : params['via'],
                                    'metric': params.get('metric'),
                                    'remove': True,
                                    'dev_id': params.get('dev_id')
                                }
                              }
    cmd_list.append(cmd)

    # Add this static route to the ACL permit filter
    if params.get('redistributeViaOSPF', False) == True:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "access-list %s permit %s" % (fwglobals.g.FRR_OSPF_ACL, params['addr'])]
                },
        }
        cmd['cmd']['descr']   =  "add %s to the allowed redistribution filter list" % params['addr']
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "no access-list %s permit %s" % (fwglobals.g.FRR_OSPF_ACL, params['addr'])]
                },
        }
        cmd['revert']['descr']   =  "remove %s from the allowed redistribution filter list" % params['addr']
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add route command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    if 'dev_id' in params:
        key = 'add-route:%s:%s:%s' % (params['addr'], params['via'], params['dev_id'])
    elif 'pci' in params: # Used for pci_to_dev_id migration only to compute the right key
        key = 'add-route:%s:%s:%s' % (params['addr'], params['via'], params['pci'])
    else:
        key = 'add-route:%s:%s' % (params['addr'], params['via'])

    if params.get('metric'):
        key += ':' + str(params['metric'])

    return key
