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
#           "pci":"0000:00:08.00"   (device, optional)
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

    if params['addr'] != 'default':
        if not 'pci' in params:
            add_cmd = [ "sudo ip route add %s via %s" % (params['addr'], params['via']) ]
            del_cmd = [ "sudo ip route del %s via %s" % (params['addr'], params['via']) ]
        else:
            add_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                        "sudo ip route add %s via %s dev DEV-STUB" % (params['addr'], params['via']) ]
            del_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                        "sudo ip route del %s via %s dev DEV-STUB" % (params['addr'], params['via']) ]
    else:  # if params['addr'] is 'default', we have to remove current default GW before adding the new one
        (old_ip, old_dev) = fwutils.get_default_route()
        old_via = old_ip if len(old_dev)==0 else '%s dev %s' % (old_ip, old_dev)
        new_ip = params['via']
        if not 'pci' in params:
            if old_via == "":
                add_cmd = [ "sudo ip route add default via %s" % (new_ip) ]
                del_cmd = [ "sudo ip route del default via %s" % (new_ip) ]
            else:
                add_cmd = [ "sudo ip route del default via %s; sudo ip route add default via %s" % (old_via, new_ip) ]
                del_cmd = [ "sudo ip route del default via %s; sudo ip route add default via %s" % (new_ip, old_via) ]
        else:
            if old_via == "":
                add_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                            "sudo ip route add default via %s dev DEV-STUB" % (new_ip) ]
                del_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                            "sudo ip route del default via %s dev DEV-STUB" % (new_ip) ]
            else:
                add_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                            "sudo ip route del default via %s; sudo ip route add default via %s dev DEV-STUB" % (old_via, new_ip) ]
                del_cmd = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'pci_to_tap', 'arg':params['pci'] } ]},
                            "sudo ip route del default via %s dev DEV-STUB; sudo ip route add default via %s" % (new_ip, old_via) ]
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "ip route add %s via %s dev %s" % (params['addr'], params['via'], str(params.get('pci')))
    cmd['cmd']['params']    = add_cmd
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "ip route del %s via %s dev %s" % (params['addr'], params['via'], str(params.get('pci')))
    cmd['revert']['params'] = del_cmd
    cmd_list.append(cmd)
    return cmd_list

def get_request_key(params):
    """Get add route command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    if 'pci' in params:
        key = 'add-route:%s:%s:%s' % (params['addr'], params['via'], params['pci'])
    else:
        key = 'add-route:%s:%s' % (params['addr'], params['via'])
    return key
