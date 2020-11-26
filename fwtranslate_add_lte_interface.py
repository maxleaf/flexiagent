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

# add__lte_interface
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
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "UP interface %s in Linux" % iface_name
    cmd['cmd']['params']    = [ "sudo ip link set dev %s up" %  iface_name]
    cmd_list.append(cmd)

    # connect the modem to the cellular provider
    apn = params['configuration']['apn'] if params['configuration'] else None
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'lte_connect',
                'args': { 'apn': apn, 'dev_id': dev_id }
    }
    cmd['cmd']['descr'] = "connect modem to lte cellular network provider"
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
                    'dhcp'      : 'no',
                    'type'      : int_type
                    },
            'substs':  [
                { 'add_param':'ip', 'val_by_func':'lte_get_provider_config', 'arg':'IP' },
                { 'add_param':'gw', 'val_by_func':'lte_get_provider_config', 'arg':'GATEWAY' }
            ]
    }
    cmd['cmd']['descr'] = "add interface into netplan config file"

    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
            'module': 'fwnetplan',
            'func': 'add_remove_netplan_interface',
            'args': { 'is_add'  : 0,
                    'dev_id'    : dev_id,
                    'ip'        : iface_addr,
                    'gw'        : gw,
                    'metric'    : metric,
                    'dhcp'      : 'no',
                    'type'      : int_type
                    },
            'substs':  [
                { 'add_param':'ip', 'val_by_func':'lte_get_provider_config', 'arg':'IP' },
                { 'add_param':'gw', 'val_by_func':'lte_get_provider_config', 'arg':'GATEWAY' }
            ]
    }
    cmd['revert']['descr'] = "remove interface from netplan config file"
    cmd_list.append(cmd)

    # Enable NAT.
    # On WAN interfaces run
    #   'nat44 add interface address GigabitEthernet0/9/0'
    #   'set interface nat44 out GigabitEthernet0/9/0 output-feature'
    # nat.api.json: nat44_add_del_interface_addr() & nat44_interface_add_del_output_feature(inside=0)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "enable NAT for interface address %s" % dev_id
    cmd['cmd']['params']    = {
                                'module': 'fwutils',
                                'func':   'vpp_nat_add_remove_interface',
                                'args':   {
                                    'remove': False,
                                    'dev_id': dev_id,
                                    'metric': metric
                                }
                                }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "disable NAT for interface %s" % dev_id
    cmd['revert']['params'] = {
                                'module': 'fwutils',
                                'func':   'vpp_nat_add_remove_interface',
                                'args':   {
                                    'remove': True,
                                    'dev_id': dev_id,
                                    'metric': metric
                                }
                                }
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

    vxlan_port = 4789
    udp_proto = 17

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "nat44_add_del_identity_mapping"
    cmd['cmd']['params']        = { 'substs': [
                                        { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                                        { 'add_param':'ip_address', 'val_by_func':'lte_dev_id_to_iface_addr_bytes', 'arg':dev_id }
                                    ],
                                    'ip_address':'', 'port':vxlan_port, 'protocol':udp_proto, 'is_add':1, 'addr_only':0 }
    cmd['cmd']['descr']         = "create nat identity mapping %s -> %s" % (params['addr'], vxlan_port)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'nat44_add_del_identity_mapping'
    cmd['revert']['params']     = { 'substs': [
                                        { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                                        { 'add_param':'ip_address', 'val_by_func':'lte_dev_id_to_iface_addr_bytes', 'arg':dev_id }
                                    ],
                                    'ip_address':'', 'port':vxlan_port, 'protocol':udp_proto, 'is_add':0, 'addr_only':0 }
    cmd['revert']['descr']      = "delete nat identity mapping %s -> %s" % (params['addr'], vxlan_port)

    cmd_list.append(cmd)

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
                'substs': [ { 'add_param':'gw', 'val_by_func':'lte_get_provider_config', 'arg':'GATEWAY' }]
    }
    cmd['cmd']['descr']         = "create static arp entry for dev_id %s" % dev_id
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "exec"
    cmd['cmd']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_provider_config', 'arg':'GATEWAY' } ]},
                            "sudo arp -s DEV-STUB 00:00:00:00:00:00" ]
    cmd['cmd']['descr'] = "set arp entry on linux for lte interface"
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "remove arp entry on linux for lte interface"
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_provider_config', 'arg':'GATEWAY' } ]},
                                "sudo arp -d DEV-STUB" ]
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_add_del_dev_ingress',
                'args': { 'dev_name': '', 'is_add': 1 },
                'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
    }
    cmd['cmd']['descr'] = "add traffic control command for linux tap interface"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_add_del_dev_ingress',
                'args': { 'dev_name'  : '', 'is_add': 0 },
                'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
    }
    cmd['revert']['descr']  = "remove traffic control command for linux tap interface"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_replace_dev_root',
                'args': { 'dev_name'  : '' },
                'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
    }
    cmd['cmd']['descr'] = "replace traffic control command for linux tap interface"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_remove_dev_root',
                'args': { 'dev_name'  : '' },
                'substs': [ { 'add_param':'dev_name', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]
    }
    cmd['revert']['descr']  = "remove replaced tc command for linux tap interface"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_add_del_dev_ingress',
                'args': { 'dev_name'  : iface_name, 'is_add': 1 }
    }
    cmd['cmd']['descr'] = "add traffic control command for lte interface"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_add_del_dev_ingress',
                'args': { 'dev_name'  : iface_name, 'is_add': 0 }
    }
    cmd['revert']['descr']  = "remove traffic control command for lte interface"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_replace_dev_root',
                'args': { 'dev_name'  : iface_name }
    }
    cmd['cmd']['descr'] = "replace traffic control command for lte interface"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'traffic_control_remove_dev_root',
                'args': { 'dev_name'  : iface_name }
    }
    cmd['revert']['descr']  = "remove replaced tc command for lte interface"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "exec"
    cmd['cmd']['params'] = [
        "tc filter add dev DEV-STUB parent ffff: \
        protocol all prio 2 u32 \
        match u32 0 0 flowid 1:1 \
        action pedit ex munge eth dst set LTE-MAC \
        pipe action mirred egress mirror dev %s" % iface_name,
        { 'substs': [
            {'replace':'DEV-STUB', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name },
            {'replace':'LTE-MAC', 'val_by_func':'get_interface_mac_addr', 'arg':iface_name }
        ] }
    ]
    cmd['cmd']['descr'] = "add filter traffic control command for tap and wwan interfaces"
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "exec"
    cmd['cmd']['params'] = [
        "tc -force filter add dev %s parent ffff: \
        protocol all prio 2 u32 \
        match u32 0 0 flowid 1:1 \
        action pedit ex munge eth dst set VPP-MAC \
        pipe action mirred egress mirror dev DEV-STUB" % iface_name,
        { 'substs': [
            {'replace':'VPP-MAC', 'val_by_func':'get_vpp_tap_interface_mac_addr', 'arg':dev_id },
            {'replace':'DEV-STUB', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name }
        ] }
    ]
    cmd['cmd']['descr'] = "add filter traffic control command for tap and wwan interfaces"
    cmd_list.append(cmd)

    # cmd = {}
    # cmd['cmd'] = {}
    # cmd['cmd']['name']   = "python"
    # cmd['cmd']['params'] = {
    #             'module': 'fwutils',
    #             'func': 'lte_update_params',
    #             'args': { 'orig_req_params': params, 'dev_id': dev_id}
    # }
    # cmd_list.append(cmd)

    return cmd_list
