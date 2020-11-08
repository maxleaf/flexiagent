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
def add_non_dpdk_interface(params):
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

    is_lte = fwutils.is_lte_interface(dev_id)

    if is_lte:
        # connect to provider
        try:
            apn = params['configuration']['apn']
        except KeyError:
            raise Exception("add_non_dpdk_interface: apn is not configured for %s interface" % iface_name)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                    'module': 'fwutils',
                    'func': 'connect_to_lte',
                    'args': {
                        'params': {
                            'dev_id'    : dev_id,
                            'apn'       : apn,
                        }
                    }
        }
        cmd['cmd']['descr'] = "connect to lte provider"
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func': 'disconnect_from_lte'
        }
        cmd['revert']['descr'] = "disconnect from lte provider"
        cmd_list.append(cmd)

    # enable DHCP packets detection in VPP
    if dhcp == 'yes':
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['descr']  = "Enable DHCP detect"
        cmd['cmd']['params'] = {
                        'module': 'fwutils',
                        'func': 'vpp_set_dhcp_detect',
                        'args': {'dev_id': dev_id, 'remove': False}
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "Disable DHCP detect"
        cmd['revert']['params'] = {
                        'module': 'fwutils',
                        'func': 'vpp_set_dhcp_detect',
                        'args': {'dev_id': dev_id, 'remove': True}
        }
        cmd_list.append(cmd)

    # The bridge solution is not for LTE interface
    if not is_lte:
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

    if not is_lte:
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
        cmd['cmd']['descr']  = "add linux interface into a bridge"

        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['params'] = [ "sudo brctl delif br_%s %s" %  (iface_name, iface_name) ]
        cmd['revert']['descr']  = "remove linux interface from a bridge"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "exec"
        cmd['cmd']['descr']     = "UP bridge br_%s in Linux" % iface_name
        cmd['cmd']['params']    = [ "sudo ip link set dev br_%s up" % iface_name]
        cmd_list.append(cmd)

    # add interface into netplan configuration
    netplan_params = {
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

    if is_lte:
        netplan_params['substs'] = [
            { 'add_param':'ip', 'val_by_func':'get_lte_info', 'arg':'IP' },
            { 'add_param':'gw', 'val_by_func':'get_lte_info', 'arg':'GATEWAY' }
        ]

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = netplan_params
    cmd['cmd']['descr'] = "add interface into netplan config file"

    cmd['revert'] = {}
    reverse_netplan_params = copy.deepcopy(netplan_params)
    reverse_netplan_params['args']['is_add'] = 0
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = reverse_netplan_params
    cmd['revert']['descr'] = "remove interface from netplan config file"
    cmd_list.append(cmd)

    # Enable NAT.
    # On WAN interfaces run
    #   'nat44 add interface address GigabitEthernet0/9/0'
    #   'set interface nat44 out GigabitEthernet0/9/0 output-feature'
    # nat.api.json: nat44_add_del_interface_addr() & nat44_interface_add_del_output_feature(inside=0)
    if 'type' not in params or params['type'].lower() == 'wan':
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "nat44_add_del_interface_addr"
        cmd['cmd']['descr']   = "enable NAT for interface %s (%s)" % (dev_id, iface_addr)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                    'is_add':1, 'twice_nat':0 }
        cmd['revert'] = {}
        cmd['revert']['name']   = "nat44_add_del_interface_addr"
        cmd['revert']['descr']  = "disable NAT for interface %s (%s)" % (dev_id, iface_addr)
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                    'is_add':0, 'twice_nat':0 }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "nat44_interface_add_del_output_feature"
        cmd['cmd']['descr']   = "add interface %s (%s) to output path" % (dev_id, iface_addr)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                    'is_add':1, 'is_inside':0 }
        cmd['revert'] = {}
        cmd['revert']['name']   = "nat44_interface_add_del_output_feature"
        cmd['revert']['descr']  = "remove interface %s (%s) from output path" % (dev_id, iface_addr)
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                    'is_add':0, 'is_inside':0 }
        cmd_list.append(cmd)

         # nat.api.json: nat44_add_del_identity_mapping (..., is_add, ...)
        vxlan_port = 4789
        udp_proto = 17

        iface_addr_bytes = ''
        if iface_addr:
            iface_addr_bytes, _ = fwutils.ip_str_to_bytes(iface_addr)

        if iface_addr_bytes or is_lte:
            substs = [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]

            if is_lte:
                substs.append({ 'add_param':'ip_address', 'val_by_func':'lte_dev_id_to_iface_addr_bytes', 'arg':dev_id })

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']          = "nat44_add_del_identity_mapping"
            cmd['cmd']['params']        = { 'ip_address':iface_addr_bytes, 'port':vxlan_port, 'protocol':udp_proto, 'is_add':1, 'addr_only':0, 'substs': substs }
            cmd['cmd']['descr']         = "create nat identity mapping %s -> %s" % (params['addr'], vxlan_port)

            cmd['revert'] = {}
            cmd['revert']['name']       = 'nat44_add_del_identity_mapping'
            cmd['revert']['params']     = { 'ip_address':iface_addr_bytes, 'port':vxlan_port, 'protocol':udp_proto, 'is_add':0, 'addr_only':0, 'substs': substs }
            cmd['revert']['descr']      = "delete nat identity mapping %s -> %s" % (params['addr'], vxlan_port)

            cmd_list.append(cmd)

    if is_lte:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                    'module': 'fwutils',
                    'func': 'vpp_add_static_arp',
                    'args': {
                            'dev_id'  : dev_id,
                            'gw'      : '',
                            'mac'     : '00:00:00:00:00:00',
                    },
                    'substs': [ { 'add_param':'gw', 'val_by_func':'get_lte_info', 'arg':'GATEWAY' }]
        }
        cmd['cmd']['descr']         = "create static arp entry for dev_id %s" % dev_id
        cmd_list.append(cmd)

        cmd['cmd'] = {}
        cmd['cmd']['name'] = "exec"
        cmd['cmd']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'get_lte_info', 'arg':'GATEWAY' } ]},
                                "sudo arp -s DEV-STUB 00:00:00:00:00:00" ]
        cmd['cmd']['descr'] = "set arp entry on linux for lte interface"
        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['descr']  = "remove arp entry on linux for lte interface"
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'get_lte_info', 'arg':'GATEWAY' } ]},
                                    "sudo arp -d DEV-STUB 00:00:00:00:00:00" ]
        cmd_list.append(cmd)

    return cmd_list
