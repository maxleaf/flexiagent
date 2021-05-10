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

def generate_bridge_id(addr):
    """Generate bridge identifier.

    :returns: New bridge identifier.
    """
    router_api_db = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    if not 'bridges' in router_api_db:
        router_api_db['bridges'] = {}

    bridge_id = router_api_db['bridges'].get(addr)
    if bridge_id:
        return bridge_id

    bridge_id = router_api_db['bridges'].get('last_bridge_id', 20000)
    bridge_id += 1
    if bridge_id >= 25000: # bridge_id is up to 16 mb in vpp
        bridge_id = 20000

    router_api_db['bridges']['last_bridge_id'] = bridge_id
    router_api_db['bridges'][addr] = bridge_id

    fwglobals.g.db['router_api'] = router_api_db
    return bridge_id

def add_bridge(params):
    """Generate commands to add a VPP l2 bridge with bvi interface.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    bridge_id = generate_bridge_id(params['addr'])

    ret_attr = 'sw_if_index'
    cache_key = 'loop_bridge_%d' % bridge_id

    # cmd = {}
    # cmd['cmd'] = {}
    # cmd['cmd']['name']      = "bridge_domain_add_del"
    # cmd['cmd']['params']    = { 'bd_id': bridge_id , 'is_add':1, 'learn':1, 'forward':1, 'uu_flood':1, 'flood':1, 'arp_term':0}
    # cmd['cmd']['descr']     = "create bridge"
    # cmd['revert'] = {}
    # cmd['revert']['name']   = 'bridge_domain_add_del'
    # cmd['revert']['params'] = { 'bd_id': bridge_id , 'is_add':0 }
    # cmd['revert']['descr']  = "delete bridge"
    # cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "create_loopback_instance"
    cmd['cmd']['params']        = { 'is_specified': 1 }
    cmd['cmd']['cache_ret_val'] = (ret_attr,cache_key)
    cmd['cmd']['descr']         = "create loopback interface (id=%d)" % bridge_id
    cmd['revert'] = {}
    cmd['revert']['name']       = 'delete_loopback'
    cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ] }
    cmd['revert']['descr']      = "delete loopback interface (id=%d)" % bridge_id
    cmd_list.append(cmd)

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

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "set %s to loopback interface in Linux" % params['addr']
    cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                "sudo ip addr add %s dev DEV-STUB" % (params['addr']) ]
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "unset %s from loopback interface in Linux" % params['addr']
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                "sudo ip addr del %s dev DEV-STUB" % (params['addr']) ]
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "UP loopback interface %s in Linux" % params['addr']
    cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                "sudo ip link set dev DEV-STUB up" ]
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "DOWN loopback interface %s in Linux" % params['addr']
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                "sudo ip link set dev DEV-STUB down" ]
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-bridge-%s' % params['addr']
    return key
