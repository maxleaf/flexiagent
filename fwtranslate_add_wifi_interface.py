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
import re

import fwglobals
import fwnetplan
import fwtranslate_revert
import fwutils

# add_interface
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-interface",
#      "params": {
#           "dev_id":"0000:00:08.00",
#           "addr":"10.0.0.4/24",
#           "routing":"ospf"
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg
#    ------------------------------------------------------------
#    01. sudo vppctl set int state 0000:00:08.00 up
#    02. sudo vppctl set int ip address 0000:00:08.00 192.168.56.107/24
#
#    2.Netplan config
#    ------------------------------------------------------------
#    03. add interface section into configuration file
#
#    3. Add interface address to ospfd.conf for FRR
#    04. add 'network 192.168.56.107/24 area 0.0.0.0' line:
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#      network 192.168.56.107/24 area 0.0.0.0
#
#    07. sudo systemctl restart frr
#
def add(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']
    iface_addr = params.get('addr', '')
    iface_name = fwutils.dev_id_to_linux_if(dev_id)


    # Add interface section into Netplan configuration file
    gw        = params.get('gateway', None)
    metric    = params.get('metric', 0)
    dhcp      = params.get('dhcp', 'no')
    int_type  = params.get('type', None)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "exec"
    cmd['cmd']['params'] = [ "sudo brctl addbr br_%s" %  iface_name ]
    cmd['cmd']['descr']  = "create linux bridge for interface %s" % iface_name

    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['params'] = [ "sudo ip link set dev br_%s down && sudo brctl delbr br_%s" %  (iface_name, iface_name) ]
    cmd['revert']['descr']  = "remove linux bridge for interface %s" % iface_name
    cmd_list.append(cmd)

    # create tap for this interface in vpp and linux
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'configure_tap_in_linux_and_vpp',
                'args': { 'linux_if_name': iface_name }
    }
    cmd['cmd']['descr'] = "create tap interface in linux and vpp"
    cmd_list.append(cmd)

    # add tap into a bridge.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "exec"
    cmd['cmd']['params'] =  [ {'substs': [ {'replace':'DEV-TAP', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]},
                                "sudo brctl addif br_%s DEV-TAP" %  iface_name ]
    cmd['cmd']['descr']  = "add tap interface of %s into the appropriate bridge" % iface_name

    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-TAP', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]},
                                "sudo brctl delif br_%s DEV-TAP" %  iface_name ]
    cmd['revert']['descr']  = "remove tap from a bridge"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "exec"
    cmd['cmd']['params'] =  [ "sudo brctl addif br_%s %s" %  (iface_name, iface_name) ]
    cmd['cmd']['descr']  = "add wifi interface into a bridge"

    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['params'] = [ "sudo brctl delif br_%s %s" %  (iface_name, iface_name) ]
    cmd['revert']['descr']  = "remove wifi interface from a bridge"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "UP bridge br_%s in Linux" % iface_name
    cmd['cmd']['params']    = [ "sudo ip link set dev br_%s up" % iface_name]
    cmd_list.append(cmd)

    # add interface into netplan configuration
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
            'module': 'fwnetplan',
            'func': 'add_remove_netplan_interface',
            'args': { 'is_add'  : 1,
                    'dev_id'    : dev_id,
                    'ip'        : iface_addr,
                    'gw'        : gw,
                    'metric'    : metric,
                    'dhcp'      : dhcp,
                    'type'      : int_type
                    }
    }
    cmd['cmd']['descr'] = "add interface into netplan config file"
    cmd['revert'] = {}
    cmd['revert']['params'] = {
            'module': 'fwnetplan',
            'func': 'add_remove_netplan_interface',
            'args': { 'is_add'  : 0,
                    'dev_id'    : dev_id,
                    'ip'        : iface_addr,
                    'gw'        : gw,
                    'metric'    : metric,
                    'dhcp'      : dhcp,
                    'type'      : int_type
                    }
    }
    cmd['revert']['name']   = "python"
    cmd['revert']['descr'] = "remove interface from netplan config file"
    cmd_list.append(cmd)

    # Configure hostapd with saved configuration
    # run hostapd
    # configure dhcp server for this interface

    return cmd_list
