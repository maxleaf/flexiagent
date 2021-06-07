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

def release_bridge_id(addr):
    router_api_db = fwglobals.g.db['router_api']
    bridges_db = router_api_db['bridges']

    bridge_id = bridges_db.get(addr)
    if not bridge_id:
        return (True, None)
    del bridges_db[addr]

    bridges_db['vacant_ids'].append(bridge_id)
    bridges_db['vacant_ids'].sort()

    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    fwglobals.g.db['router_api'] = router_api_db

def get_bridge_id(addr):
    router_api_db = fwglobals.g.db['router_api']
    bridges_db = router_api_db['bridges']
    return bridges_db.get(addr)

def allocate_bridge_id(addr, result_cache=None):
    """Get bridge identifier.

    :returns: A bridge identifier.
    """
    router_api_db = fwglobals.g.db['router_api']
    bridges_db = router_api_db['bridges']

    # Check if bridge id already created for this address
    bridge_id = get_bridge_id(addr)

    # Allocate new id
    if not bridge_id:
        if not 'vacant_ids' in bridges_db:
            return (None, "Failed to allocate bridge id. vacant_ids is empty")
        bridge_id = bridges_db['vacant_ids'].pop(0)

    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    router_api_db['bridges'][addr] = bridge_id
    fwglobals.g.db['router_api'] = router_api_db

    # Store 'bridge_id' in cache if provided by caller.
    #
    if result_cache and result_cache['result_attr'] == 'bridge_id':
        key = result_cache['key']
        result_cache['cache'][key] = bridge_id

    return (bridge_id, None)

def add_switch(params):
    """Generate commands to add a VPP l2 bridge with bvi interface.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    addr = params['addr']

    bridge_ret_attr = 'bridge_id'
    bridge_cache_key = 'bridge_id_%s' % addr
    loopback_ret_attr = 'sw_if_index'
    loopback_cache_key = 'loop_bridge_%s' % addr

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "get bridge id for address %s" % addr
    cmd['cmd']['cache_ret_val'] = (bridge_ret_attr, bridge_cache_key)
    cmd['cmd']['params']    = {
        'module': 'fwtranslate_add_switch',
        'func':   'allocate_bridge_id',
        'args':   {
            'addr': addr,
        }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove bridge id for address %s" % addr
    cmd['revert']['params'] = {
        'module': 'fwtranslate_add_switch',
        'func':   'release_bridge_id',
        'args':   {
            'addr': addr,
        }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "bridge_domain_add_del"
    cmd['cmd']['params']    = { 'substs': [ { 'add_param':'bd_id', 'val_by_key':bridge_cache_key} ],
                                'is_add':1, 'learn':1, 'forward':1, 'uu_flood':1, 'flood':1, 'arp_term':0}
    cmd['cmd']['descr']     = "create bridge for %s" % addr
    cmd['revert'] = {}
    cmd['revert']['name']   = 'bridge_domain_add_del'
    cmd['revert']['params'] = { 'substs': [ { 'add_param':'bd_id', 'val_by_key':bridge_cache_key} ],
                                'is_add':0 }
    cmd['revert']['descr']  = "delete bridge for %s" % addr
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "create_loopback_instance"
    cmd['cmd']['params']        = { 'substs': [ { 'add_param':'user_instance', 'val_by_key':bridge_cache_key} ],
                                    'is_specified': 1 }
    cmd['cmd']['cache_ret_val'] = (loopback_ret_attr, loopback_cache_key)
    cmd['cmd']['descr']         = "create loopback interface for bridge %s" % addr
    cmd['revert'] = {}
    cmd['revert']['name']       = 'delete_loopback'
    cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':loopback_cache_key} ] }
    cmd['revert']['descr']      = "delete loopback interface for bridge %s" % addr
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_l2_bridge"
    cmd['cmd']['descr']   = "add loop interface to bridge %s" % addr
    cmd['cmd']['params']  = {   'substs': [
                                    { 'add_param':'rx_sw_if_index', 'val_by_key':loopback_cache_key},
                                    { 'add_param':'bd_id', 'val_by_key':bridge_cache_key}
                                ],
                                'enable':1, 'port_type':1 # port_type 1 stands for BVI (see test\vpp_l2.py)
                            }
    cmd['revert'] = {}
    cmd['revert']['name']   = "sw_interface_set_l2_bridge"
    cmd['revert']['descr']  = "remove loop interface from bridge %s" % addr
    cmd['revert']['params'] = { 'substs': [
                                    { 'add_param':'rx_sw_if_index', 'val_by_key':loopback_cache_key},
                                    { 'add_param':'bd_id', 'val_by_key':bridge_cache_key}
                                ],
                                'enable':0
                            }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "set %s to loopback interface in Linux" % addr
    cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':loopback_cache_key} ]},
                                "sudo ip addr add %s dev DEV-STUB" % addr ]
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "unset %s from loopback interface in Linux" % addr
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':loopback_cache_key} ]},
                                "sudo ip addr del %s dev DEV-STUB" % addr ]
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "exec"
    cmd['cmd']['descr']     = "UP loopback interface %s in Linux" % addr
    cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':loopback_cache_key} ]},
                                "sudo ip link set dev DEV-STUB up" ]
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "DOWN loopback interface %s in Linux" % addr
    cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':loopback_cache_key} ]},
                                "sudo ip link set dev DEV-STUB down" ]
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-lte key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-lte request.
    """
    key = 'add-switch-%s' % params['addr']
    return key
