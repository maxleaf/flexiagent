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

import fwglobals

def generate_bridge_id():
    """Generate bridge identifier.

    :returns: New bridge identifier.
    """
    router_api_db = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    if not 'bridge_id' in router_api_db:
        router_api_db['bridge_id'] = 0

    bridge_id = router_api_db['bridge_id']
    bridge_id += 1
    if bridge_id >= 16777215: # bridge_id is up to 16 mb in vpp
        bridge_id = 0
    router_api_db['bridge_id'] = bridge_id

    fwglobals.g.db['router_api'] = router_api_db
    return bridge_id

def add_bridge(params):
    """Generate commands to add a VPP l2 bridge with bvi interface.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    bridge_id = generate_bridge_id()

    ret_attr = 'sw_if_index'
    cache_key = 'loop_bridge_%d' % bridge_id

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "create_loopback_instance"
    cmd['cmd']['params']        = { 'is_specified': 1, 'user_instance': bridge_id }
    cmd['cmd']['cache_ret_val'] = (ret_attr,cache_key)
    cmd['cmd']['descr']         = "create loopback interface (id=%d)" % bridge_id
    cmd['revert'] = {}
    cmd['revert']['name']       = 'delete_loopback'
    cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ] }
    cmd['revert']['descr']      = "delete loopback interface (id=%d)" % bridge_id

    # cmd = {}
    # cmd['cmd'] = {}
    # cmd['cmd']['name']    = "exec"
    # cmd['cmd']['descr']   = "create loopback interface for a bridge"
    # cmd['cmd']['params'] =  ["sudo vppctl loop create"]
    # cmd['revert'] = {}
    # cmd['revert']['name']   = "exec"
    # cmd['revert']['descr']   = "remove loopback interface"
    # cmd['revert']['params'] =  ["sudo vppctl loop delete intfc loop0"]
    # cmd_list.append(cmd)


    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_l2_bridge"
    cmd['cmd']['descr']   = "add loop interface to bridge %d" % bridge_id
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'rx_sw_if_index', 'val_by_key':cache_key} ],
                              'bd_id':bridge_id , 'enable':1, 'port_type':1 }         # port_type 1 stands for BVI (see test\vpp_l2.py)
    cmd['revert'] = {}
    cmd['revert']['name']   = 'sw_interface_set_l2_bridge'
    cmd['revert']['descr']  = "remove loop interface from bridge %d" % bridge_id
    cmd['revert']['params'] = { 'substs': [ { 'add_param':'rx_sw_if_index', 'val_by_key':cache_key} ],
                              'bd_id':bridge_id , 'enable':0 }
    cmd_list.append(cmd)


    # cmd = {}
    # cmd['cmd'] = {}
    # cmd['cmd']['name']    = "exec"
    # cmd['cmd']['descr']   = "set interface to l2 bridge"
    # cmd['cmd']['params'] =  [
    #     { 'substs': [
    #             { 'replace':'VPP-LOOP', 'val_by_func':'dev_id_to_vpp_if_name', 'arg':dev_id },
    #             { 'replace':'BRIDGE-ID', 'val_by_func':'iface_addr_to_bridge_id', 'arg':iface_addr },
    #         ]
    #     },
    #     "sudo vppctl set interface l2 bridge VPP-LOOP %s bvi" % bridge_id
    # ]
    # cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-bridge-%s' % params['addr']
    return key
