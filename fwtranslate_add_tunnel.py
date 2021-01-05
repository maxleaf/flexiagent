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
import ipaddress
import os

import fwutils
import fwglobals
import socket

from netaddr import *
from vpp_papi import VppEnum

# add_tunnel
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "add-tunnel",
#      "params": {
#        "src": "8.8.1.1"
#        "dst": "8.8.1.2"
#        "ipsec": {
#          "local-sa": {
#             "spi": 1020,
#             "crypto-alg": "aes-cbc-128",
#             "crypto-key": "1020aa794f574265564551694d653768",
#             "integr-alg":  "sha1-96",
#             "integr-key":  "1020ff4b55523947594d6d3547666b45764e6a58"
#          },
#          "remote-sa": {
#             "spi": 2010,
#             "crypto-alg": "aes-cbc-128",
#             "crypto-key": "2010aa794f574265564551694d653768",
#             "integr-alg":  "sha1-96",
#             "integr-key":  "2010ff4b55523947594d6d3547666b45764e6a58"
#          }
#        },
#        "loopback-iface": {
#          "addr":"10.100.0.7/31",
#          "mac":"02:00:27:fd:00:07",
#          "mtu":1420,
#          "routing":"ospf"
#        }
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg:
#       - create GRE tunnel
#       - create loopback 0 interface for FRR to run OSPF through it
#       - set GRE tunnel and loopback 0 into bridge
#       - create VxLAN tunnel
#       - create loopback 1 interface
#       - set VxLAN tunnel and loopback 1 into bridge
#       - give the GRE tunnel source and destination addresses of
#         local and remote loopback 1 interfaces, so vpp will route
#         packets rewrote by GRE through the loopback 1 interface.
#    -----------------------------------------------------------------
#    create loopback interface
#    set int ip address loop0 10.100.0.7/31
#    set int mac address loop0 02:00:27:fd:00:07
#    set int mtu 1420 loop0
#    set int l2 learn loop0 disable
#    set int state loop0 up
#
#    create loopback interface
#    set int ip address loop1 10.101.0.7/31
#    set int mac address loop1 02:00:27:fe:00:07
#    set int mtu 9000 loop1
#    set int l2 learn loop1 disable
#    set int state loop1 up
#
#    ipsec sa add 21 spi 1020 esp crypto-alg aes-cbc-128 crypto-key 1020aa794f574265564551694d653768 integr-alg sha1-96 integr-key 1020ff4b55523947594d6d3547666b45764e6a58
#    ipsec sa add 22 spi 2010 espcrypto-alg aes-cbc-128 crypto-key 2010aa794f574265564551694d653768 integr-alg sha1-96 integr-key 2010ff4b55523947594d6d3547666b45764e6a58
#
#    create gre tunnel src 10.101.0.7 dst 10.101.0.6 teb
#    ipsec tunnel protect gre0 sa-in 10 sa-out 20
#    set int state ipsec-gre0 up
#    set int l2 bridge loop0 1 bvi
#    set int l2 bridge ipsec_gre0 1 1
#
#    create vxlan tunnel src 8.8.1.1 dst 8.8.2.1 vni 1
#    set int state vxlan_tunnel0 up
#    set int l2 bridge loop0 1 bvi
#    set int l2 bridge vxlan_tunnel0 1 1
#
#    2.Linux.sh:
#       - configure loopback tap in Linux
#    ------------------------------------------------------------
#    sudo ip addr add 10.100.0.7/31 dev vpp2  (vpp2 is Linux name for vpp loop0)
#    sudo ip link set dev vpp2 up
#
#    3.Linux.sh:
#       - update ospfd.conf with loopback interface:
#    ------------------------------------------------------------
#    Add "  network 10.100.0.7/31 area 0.0.0.0" into 'router ospf' section
#    Mark it as point-to-point:
#           !
#               interface vpp2
#               ip ospf network point-to-point
#           !
#        So final ospfd.conf should look like:
#            hostname ospfd
#            password zebra
#            log file /var/log/frr/ospfd.log informational
#            log stdout
#            !
#            interface vpp2
#              ip ospf network point-to-point
#            !
#            router ospf
#             ospf router-id 192.168.56.101
#             network 192.168.56.0/24 area 0.0.0.0
#             network 10.100.0.7/31 area 0.0.0.0
#    sudo systemctl restart
#
#  This command sequence implements following scheme:
#
#     +--------------------------------------------------------------------------------+
#     |                                     LINUX                                      |
#     |              10.100.0.7                                                        |
#     |  +--------+  +--------+                                             +--------+ |
#     |  |tap/vpp0|  |tap/vpp2|                                             |tap/vpp1| |
#     +--+--------+--+--------+---------------------------------------------+--------+-+
#   --|--|  LAN   |--| loop0  |--bridge_l2gre-ipsec --- loop1-bridge-vxlan--|  WAN   |-|--
#     |  +--------+  +--------+                       10.101.0.7            +--------+ |
#     |              10.100.0.7                                                        |
#     |                                       VPP                                      |
#     +--------------------------------------------------------------------------------+
#

def generate_sa_id():
    """Generate SA identifier.

    :returns: New SA identifier.
    """
    router_api_db = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    sa_id = router_api_db['sa_id']
    sa_id += 1
    if sa_id == 2**32:       # sad_id is u32 in VPP
        sa_id = 0
    router_api_db['sa_id'] = sa_id

    fwglobals.g.db['router_api'] = router_api_db
    return sa_id

def _add_loopback(cmd_list, cache_key, iface_params, id, internal=False):
    """Add loopback command into the list.

    :param cmd_list:            List of commands.
    :param cache_key:           Cache key of the tunnel to be used by others.
    :param mac:                 MAC address.
    :param addr:                IP address.
    :param mtu:                 MTU value.
    :param internal:            Hide from Linux.

    :returns: None.
    """
    # --------------------------------------------------------------------------
    #    create loopback interface
    #    set int ip address loop0 10.100.0.2/31
    #    set int mac address loop0 08:00:27:fd:12:01
    #    set int mtu 1420 loop0
    # --------------------------------------------------------------------------

    addr = iface_params['addr']
    mac  = iface_params['mac']
    mtu  = iface_params['mtu']

    # ret_attr  - attribute of the object returned by command,
    #             value of which is stored in cache to be available
    #             for next commands.
    # cache_key - key in cache, where the value
    #             of the 'ret_attr' attribute is stored.
    ret_attr = 'sw_if_index'
    mac_bytes = fwutils.mac_str_to_bytes(mac)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "create_loopback_instance"
    cmd['cmd']['params']        = { 'mac_address':mac_bytes, 'is_specified': 1, 'user_instance': id }
    cmd['cmd']['cache_ret_val'] = (ret_attr,cache_key)
    cmd['cmd']['descr']         = "create loopback interface (mac=%s, id=%d)" % (mac, id)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'delete_loopback'
    cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ] }
    cmd['revert']['descr']      = "delete loopback interface (mac=%s, id=%d)" % (mac, id)
    cmd_list.append(cmd)

    # l2.api.json: l2_flags (..., sw_if_index, bd_id, is_set, flags, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "l2_flags"
    cmd['cmd']['descr']   = "disable learning on loopback interface %s" % addr
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                              'is_set':0 , 'feature_bitmap':1 }  # 1 stands for LEARN (see test\test_l2bd_multi_instance.py)
    cmd_list.append(cmd)

    if internal:
        # interface.api.json: sw_interface_add_del_address (..., sw_if_index, is_add, prefix, ...)
        # 'sw_if_index' is returned by the previous command and it is stored in the executor cache.
        # So executor takes it out of the cache while executing this command.
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "sw_interface_add_del_address"
        cmd['cmd']['descr']     = "set %s to loopback interface" % addr
        cmd['cmd']['params']    = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                    'is_add':1, 'prefix':addr }
        cmd['revert'] = {}
        cmd['revert']['name']   = "sw_interface_add_del_address"
        cmd['revert']['descr']  = "unset %s from loopback interface" % addr
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                    'is_add':0, 'prefix':addr }
        cmd_list.append(cmd)

        # interface.api.json: sw_interface_set_flags (..., sw_if_index, flags, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "sw_interface_set_flags"
        cmd['cmd']['descr']     = "UP loopback interface %s" % addr
        cmd['cmd']['params']    = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                    'flags':1 # VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
                                  }
        cmd['revert'] = {}
        cmd['revert']['name']   = "sw_interface_set_flags"
        cmd['revert']['descr']  = "DOWN loopback interface %s" % addr
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                    'flags':0 }
        cmd_list.append(cmd)

    # interface.api.json: sw_interface_set_mtu (..., sw_if_index, mtu, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_mtu"
    cmd['cmd']['descr']   = "set mtu=%s to loopback interface" % mtu
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                              'mtu': [ mtu , 0, 0, 0 ] }
    cmd_list.append(cmd)

    # interface.api.json: sw_interface_flexiwan_label_add_del (..., sw_if_index, n_labels, labels, ...)
    if 'multilink' in iface_params and 'labels' in iface_params['multilink']:
        labels = iface_params['multilink']['labels']
        if len(labels) > 0:
            # next_hop is remote end of tunnel, which is XOR(local_end, 0.0.0.1)
            next_hop = str(IPNetwork(addr).ip ^ IPAddress("0.0.0.1"))
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "python"
            cmd['cmd']['descr']   = "add multilink labels into loopback interface %s: %s" % (addr, labels)
            cmd['cmd']['params']  = {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels': labels, 'next_hop': next_hop, 'remove': False }
            }
            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['descr']  = "remove multilink labels from loopback interface %s: %s" % (addr, labels)
            cmd['revert']['params'] = {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels': labels, 'next_hop': next_hop, 'remove': True }
            }
            cmd_list.append(cmd)

    # Configure tap of loopback interface in Linux
    # ------------------------------------------------------------
    # sudo ip addr add <loopback ip> dev <tap of loopback iface>
    # sudo ip link set dev <tap of loopback iface> up
    # sudo ip link set dev <tap of loopback iface> mtu <mtu of loopback iface>  // ensure length of Linux packets + overhead of vpp gre & ipsec & vxlan is below 1500
    if not internal:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "exec"
        cmd['cmd']['descr']     = "set %s to loopback interface in Linux" % addr
        cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                    "sudo ip addr add %s dev DEV-STUB" % (addr) ]
        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['descr']  = "unset %s from loopback interface in Linux" % addr
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                    "sudo ip addr del %s dev DEV-STUB" % (addr) ]
        cmd_list.append(cmd)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "exec"
        cmd['cmd']['descr']     = "UP loopback interface %s in Linux" % addr
        cmd['cmd']['params']    = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                    "sudo ip link set dev DEV-STUB up" ]
        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['descr']  = "DOWN loopback interface %s in Linux" % addr
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                    "sudo ip link set dev DEV-STUB down" ]
        cmd_list.append(cmd)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   = "set mtu=%s into loopback interface %s in Linux" % (mtu, addr)
        cmd['cmd']['params']  = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':cache_key} ]},
                                "sudo ip link set dev DEV-STUB mtu %s" % mtu ]
        cmd_list.append(cmd)

def _add_bridge(cmd_list, bridge_id):
    """Add bridge command into the list.

    :param cmd_list:            List of commands.
    :param bridge_id:           Bridge identifier.

    :returns: None.
    """
    # l2.api.json: bridge_domain_add_del (..., bd_id, is_add, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "bridge_domain_add_del"
    cmd['cmd']['params']    = { 'bd_id':bridge_id , 'is_add':1, 'learn':0, 'forward':1, 'uu_flood':1, 'flood':1, 'arp_term':1 }
    cmd['cmd']['descr']     = "create bridge"
    cmd['revert'] = {}
    cmd['revert']['name']   = 'bridge_domain_add_del'
    cmd['revert']['params'] = { 'bd_id':bridge_id , 'is_add':0 }
    cmd['revert']['descr']  = "delete bridge"
    cmd_list.append(cmd)

def _add_interface_to_bridge(cmd_list, iface_description, bridge_id, bvi, shg, cache_key):
    """Add interface to bridge command into the list.

    :param cmd_list:            List of commands.
    :param iface_description:   Interface name.
    :param bridge_id:           Bridge identifier.
    :param bvi:                 Use BVI.
    :param shg:                 Split horizon group number.
    :param cache_key:           Cache key of the tunnel to be used by others.

    :returns: None.
    """
    # l2.api.json: sw_interface_set_l2_bridge (..., rx_sw_if_index, bd_id, port_type, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_l2_bridge"
    cmd['cmd']['descr']   = "add interface %s to bridge" % iface_description
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'rx_sw_if_index', 'val_by_key':cache_key} ],
                              'bd_id':bridge_id , 'enable':1, 'port_type':bvi, 'shg':shg }         # port_type 1 stands for BVI (see test\vpp_l2.py)
    cmd['revert'] = {}
    cmd['revert']['name']   = 'sw_interface_set_l2_bridge'
    cmd['revert']['descr']  = "remove interface %s from bridge" % iface_description
    cmd['revert']['params'] = { 'substs': [ { 'add_param':'rx_sw_if_index', 'val_by_key':cache_key} ],
                              'bd_id':bridge_id , 'enable':0 }
    cmd_list.append(cmd)

def _add_gre_tunnel(cmd_list, cache_key, src, dst, local_sa_id, remote_sa_id):
    """Add GRE tunnel command into the list.

    :param cmd_list:             List of commands.
    :param cache_key:            Cache key of the tunnel to be used by others.
    :param src:                  Source ip address.
    :param dst:                  Destination ip address.
    :param local_sa_id:          Local SA identifier.
    :param remote_sa_id:         Remote SA identifier.

    :returns: None.
    """
    # gre.api.json: gre_tunnel_add_del (..., is_add, tunnel <type vl_api_gre_tunnel_type_t>, ...)
    ret_attr = 'sw_if_index'
    src_ip = src.split('/')[0]
    dst_ip = dst.split('/')[0]
    tunnel = {
        'src': src_ip,
        'dst': dst_ip,
        'instance': 0xffffffff,
        'type': 1, # VppEnum.vl_api_gre_tunnel_type_t.GRE_API_TUNNEL_TYPE_TEB,
        'mode': 0  # VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_P2P
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "gre_tunnel_add_del"
    cmd['cmd']['params']        = {'is_add': 1, 'tunnel': tunnel}
    cmd['cmd']['cache_ret_val'] = (ret_attr , cache_key)
    cmd['cmd']['descr']         = "create gre tunnel %s -> %s" % (src, dst)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'gre_tunnel_add_del'
    cmd['revert']['params']     = {'is_add': 0, 'tunnel': tunnel}
    cmd['revert']['descr']      = "delete gre tunnel %s -> %s" % (src, dst)
    cmd_list.append(cmd)

    # ipsec.api.json: ipsec_tunnel_protect_update (..., tunnel <type vl_api_ipsec_tunnel_protect_t>, ...)
    tunnel = {
        'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
        'n_sa_in': 1,
        'sa_out': remote_sa_id,
        'sa_in': [local_sa_id],
        'nh': "0.0.0.0"}

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "ipsec_tunnel_protect_update"
    cmd['cmd']['params']        = {'tunnel': tunnel}
    cmd['cmd']['descr']         = "add tunnel ipsec protect %s -> %s" % (src, dst)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'ipsec_tunnel_protect_del'
    cmd['revert']['params']     = {'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ], 'nh': "0.0.0.0"}
    cmd['revert']['descr']      = "delete tunnel ipsec protect %s -> %s" % (src, dst)
    cmd_list.append(cmd)

    # interface.api.json: sw_interface_set_flags (..., sw_if_index, flags, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_flags"
    cmd['cmd']['descr']   = "UP GRE tunnel %s -> %s" % (src, dst)
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                              'flags':1 # VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
                            }
    cmd_list.append(cmd)

def _add_vxlan_tunnel(cmd_list, cache_key, bridge_id, src, dst, params):
    """Add VxLAN tunnel command into the list.

    :param cmd_list:             List of commands.
    :param cache_key:            Cache key of the tunnel to be used by others.
    :param bridge_id:            Bridge identifier.
    :param src:                  Source ip address.
    :param src:                  Destination ip address.
    :param dest_port:            Destination port after STUN resolution

    :returns: None.
    """
    # vxlan.api.json: vxlan_add_del_tunnel (..., is_add, tunnel <type vl_api_vxlan_add_del_tunnel_t>, ...)
    ret_attr = 'sw_if_index'
    src_addr = ipaddress.ip_address(src)
    dst_addr = ipaddress.ip_address(dst)
    cmd_params = {
            'is_add'               : 1,
            'src_address'          : src_addr,
            'dst_address'          : dst_addr,
            'vni'                  : bridge_id,
            'dest_port'            : int(params.get('dstPort', 4789)),
            'substs': [{'add_param': 'next_hop_sw_if_index', 'val_by_func': 'pci_to_vpp_sw_if_index', 'arg': params['pci']},
                       {'add_param': 'next_hop_ip', 'val_by_func': 'get_binary_interface_gateway_by_pci', 'arg': params['pci']}],
            'instance'             : bridge_id,
            'decap_next_index'     : 1 # VXLAN_INPUT_NEXT_L2_INPUT, vpp/include/vnet/vxlan/vxlan.h
    }
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "vxlan_add_del_tunnel"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['cache_ret_val'] = (ret_attr , cache_key)
    cmd['cmd']['descr']         = "create vxlan tunnel %s -> %s" % (src, dst)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'vxlan_add_del_tunnel'
    cmd['revert']['params']     = copy.deepcopy(cmd_params)
    cmd['revert']['params']['is_add'] = 0
    cmd['revert']['descr']      = "delete vxlan tunnel %s -> %s" % (src, dst)
    cmd_list.append(cmd)

    # interface.api.json: sw_interface_set_flags (..., sw_if_index, flags, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_flags"
    cmd['cmd']['descr']   = "UP vxlan tunnel %s -> %s" % (src, dst)
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                              'flags':1 # VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
                            }
    cmd_list.append(cmd)

def _add_ipsec_sa(cmd_list, local_sa, local_sa_id):
    """Add IPSEC sa command into the list.

    :param cmd_list:            List of commands.
    :param local_sa:            SA parameters.
    :param local_sa_id:         SA identifier.

    :returns: None.
    """
    # --------------------------------------------------------------------------
    #    ipsec sa add 21 spi 1020 esp crypto-alg aes-cbc-128 crypto-key 1020aa794f574265564551694d653768 integr-alg sha1-96 integr-key 1020ff4b55523947594d6d3547666b45764e6a58
    #    ipsec sa add 22 spi 2010 esp crypto-alg aes-cbc-128 crypto-key 2010aa794f574265564551694d653768 integr-alg sha1-96 integr-key 2010ff4b55523947594d6d3547666b45764e6a58
    # --------------------------------------------------------------------------

    #vpp/src/vnet/ipsec/ipsec.h
    crypto_algs = {
        "aes-cbc-128":  1,
        "aes-cbc-192":  2,
        "aes-cbc-256":  3,
        "aes-ctr-128":  4,
        "aes-ctr-192":  5,
        "aes-ctr-256":  6,
        "aes-gcm-128":  7,
        "aes-gcm-192":  8,
        "aes-gcm-256":  9,
        "des-cbc":      10,
        "3des-cbc":     11
    }
    integr_algs = {
        "md5-96":       1,
        "sha1-96":      2,
        "sha-256-96":   3,
        "sha-256-128":  4,
        "sha-384-192":  5,
        "sha-512-256":  6
    }

    # ipsec.api.json: ipsec_sad_entry_add_del (..., is_add, entry <type vl_api_ipsec_sad_entry_t>, ...)
    if not local_sa['crypto-alg'] in crypto_algs:
        raise Exception("fwtranslate_add_tunnel: crypto-alg %s is not supported" % local_sa['crypto-alg'])
    if not local_sa['integr-alg'] in integr_algs:
        raise Exception("fwtranslate_add_tunnel: integr-alg %s is not supported" % local_sa['integr-alg'])

    crypto_alg  = crypto_algs[local_sa['crypto-alg']]
    integr_alg  = integr_algs[local_sa['integr-alg']]
    crypto_key  = fwutils.hex_str_to_bytes(str(local_sa['crypto-key']))  # str() is needed in Python 2
    integr_key  = fwutils.hex_str_to_bytes(str(local_sa['integr-key']))

    entry = {
        'sad_id': local_sa_id,
        'spi': local_sa['spi'],
        'protocol': socket.IPPROTO_ESP,
        'crypto_algorithm': crypto_alg,
        'crypto_key': {
            'data': crypto_key,
            'length': len(crypto_key),
        },
        'integrity_algorithm': integr_alg,
        'integrity_key': {
            'data': integr_key,
            'length': len(integr_key),
        }
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "ipsec_sad_entry_add_del"
    cmd['cmd']['params']  = {'is_add': 1, 'entry': entry}
    cmd['cmd']['descr']   = "add SA rule no.%d (spi=%d, crypto=%s, integrity=%s)" % (local_sa_id, local_sa['spi'], local_sa['crypto-alg'] , local_sa['integr-alg'])
    cmd['revert'] = {}
    cmd['revert']['name']   = 'ipsec_sad_entry_add_del'
    cmd['revert']['params'] = {'is_add': 0, 'entry': entry}
    cmd['revert']['descr']  = "remove SA rule no.%d (spi=%d, crypto=%s, integrity=%s)" % (local_sa_id, local_sa['spi'], local_sa['crypto-alg'] , local_sa['integr-alg'])
    cmd_list.append(cmd)

def _add_ikev2_common_profile(cmd_list, name, tunnel_id, remote_device_id, certificate, bridge_id, src):
    """Add IKEv2 common profile commands into the list.

    :param cmd_list:            List of commands.
    :param name:                Profile name.
    :param tunnel_id:           Tunnel id.
    :param remote_device_id:    Remote device id.
    :param certificate:         Remote device public certificate.
    :param bridge_id:           Bridge id to add GRE tunnel to.
    :param src:                 GRE tunnel source ip.

    :returns: None.
    """
    machine_id = fwutils.get_machine_id()

    # Add public certificate file
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "add IKEv2 public certificate for %s" % remote_device_id
    cmd['cmd']['params']    = {
                                'module': 'fwutils',
                                'func'  : 'ikev2_add_public_certificate',
                                'args'  : {'device_id': remote_device_id, 'certificate': certificate}
                                }
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_add_del (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_add_del"
    cmd['cmd']['params']    = { 'name':name , 'is_add':1 }
    cmd['cmd']['descr']     = "create IKEv2 profile %s" % name
    cmd['revert'] = {}
    cmd['revert']['name']   = 'ikev2_profile_add_del'
    cmd['revert']['params'] = { 'name':name , 'is_add':0 }
    cmd['revert']['descr']  = "delete IKEv2 profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_auth (..., auth_method: IKEV2_AUTH_METHOD_RSA_SIG)
    data = fwutils.ikev2_remote_certificate_filename_get(remote_device_id)
    auth_method = 1 # IKEV2_AUTH_METHOD_RSA_SIG
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_auth"
    cmd['cmd']['params']    = { 'name':name, 'auth_method':auth_method, 'data':data, 'data_len':len(data) }
    cmd['cmd']['descr']     = "set IKEv2 auth method, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_local_key (...)
    key_file = fwutils.ikev2_private_key_filename_get()
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_local_key"
    cmd['cmd']['params']    = { 'key_file':str(key_file) }
    cmd['cmd']['descr']     = "set IKEv2 local key, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_id (..., 'is_local':1)
    id_type = 2 # IKEV2_ID_TYPE_ID_FQDN
    data = machine_id + '-' + str(tunnel_id)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_id"
    cmd['cmd']['params']    = { 'name':name, 'is_local':1, 'id_type':id_type, 'data':data, 'data_len':len(data) }
    cmd['cmd']['descr']     = "set IKEv2 local id, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_id (..., 'is_local':0)
    id_type = 2 # IKEV2_ID_TYPE_ID_FQDN
    data = remote_device_id + '-' + str(tunnel_id)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_id"
    cmd['cmd']['params']    = { 'name':name, 'is_local':0, 'id_type':id_type, 'data':data, 'data_len':len(data) }
    cmd['cmd']['descr']     = "set IKEv2 local id, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_ts (..., 'is_local':1)
    proto = 0
    start_port = 0
    end_port = 65535
    start_addr = IPAddress('0.0.0.0').value
    end_addr = IPAddress('255.255.255.255').value
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_ts"
    cmd['cmd']['params']    = { 'name':name, 'is_local':1, 'proto':proto, 'start_port':start_port, 'end_port':end_port, 'start_addr':start_addr, 'end_addr':end_addr }
    cmd['cmd']['descr']     = "set IKEv2 traffic selector, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_ts (..., 'is_local':0)
    proto = 0
    start_port = 0
    end_port = 65535
    start_addr = IPAddress('0.0.0.0').value
    end_addr = IPAddress('255.255.255.255').value
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_ts"
    cmd['cmd']['params']    = { 'name':name, 'is_local':0, 'proto':proto, 'start_port':start_port, 'end_port':end_port, 'start_addr':start_addr, 'end_addr':end_addr }
    cmd['cmd']['descr']     = "set IKEv2 traffic selector, profile %s" % name
    cmd_list.append(cmd)

    # Asynchronously add IKEv2 GRE tunnel into bridge
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "add IKEv2 GRE tunnel into bridge"
    cmd['cmd']['params']    = {
                                'module': 'fwutils',
                                'func'  : 'ikev2_gre_bridge_add',
                                'args'  : {'src': src, 'bridge_id': bridge_id}
                                }
    cmd_list.append(cmd)

def _add_ikev2_initiator_profile(cmd_list, name, lifetime, cache_key, responder_address, ike, esp):
    """Add IKEv2 initiator profile commands into the list.

    :param cmd_list:            List of commands.
    :param name:                Profile name.
    :param lifetime:            Connection life time.
    :param cache_key:           Interface with responder.
    :param responder_address:   Responder IP address.
    :param ike:                 IKEv2 crypto params.
    :param esp:                 ESP crypto params.

    :returns: None.
    """
    #vpp/src/plugins/ikev2/ikev2.h
    crypto_algs = {
        "des-iv64":     1,
        "des":          2,
        "3des":         3,
        "rc5":          4,
        "idea":         5,
        "cast":         6,
        "blowfish":     7,
        "3idea":        8,
        "des-iv32":     9,
        "null":         11,
        "aes-cbc":      12,
        "aes-ctr":      13,
        "aes-gcm-16":   20
    }

    integ_algs = {
        "none":              0,
        "md5-96":            1,
        "sha1-96":           2,
        "des-mac":           3,
        "kpdk-md5":          4,
        "aes-xcbc-96":       5,
        "md5-128":           6,
        "sha1-160":          7,
        "cmac-96":           8,
        "aes-128-gmac":      9,
        "aes-192-gmac":      10,
        "aes-256-gmac":      11,
        "hmac-sha2-256-128": 12,
        "hmac-sha2-384-192": 13,
        "hmac-sha2-512-256": 14
    }

    dh_type_algs = {
        "none":              0,
        "modp-768":          1,
        "modp-1024":         2,
        "modp-1536":         5,
        "modp-2048":         14,
        "modp-3072":         15,
        "modp-4096":         16,
        "modp-6144":         17,
        "modp-8192":         18,
        "ecp-256":           19,
        "ecp-384":           20,
        "ecp-521":           21,
        "modp-1024-160":     22,
        "modp-2048-224":     23,
        "modp-2048-256":     24,
        "ecp-192":           25
    }

    if not ike['crypto-alg'] in crypto_algs:
        raise Exception("_add_ikev2_initiator_profile: ike crypto-alg %s is not supported" % ike['crypto-alg'])
    if not esp['crypto-alg'] in crypto_algs:
        raise Exception("_add_ikev2_initiator_profile: esp crypto-alg %s is not supported" % esp['crypto-alg'])
    if not ike['integ-alg'] in integ_algs:
        raise Exception("_add_ikev2_initiator_profile: ike integ-alg %s is not supported" % ike['integ-alg'])
    if not esp['integ-alg'] in integ_algs:
        raise Exception("_add_ikev2_initiator_profile: esp integ-alg %s is not supported" % esp['integ-alg'])
    if not ike['dh-group'] in dh_type_algs:
        raise Exception("_add_ikev2_initiator_profile: ike dh-group %s is not supported" % ike['dh-group'])
    if not esp['dh-group'] in dh_type_algs:
        raise Exception("_add_ikev2_initiator_profile: esp dh-group %s is not supported" % esp['dh-group'])

    # ikev2.api.json: ikev2_set_responder (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_responder"
    cmd['cmd']['params']    = { 'name':name,
                                'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                'address':responder_address }
    cmd['cmd']['descr']     = "set IKEv2 responder, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_ike_transforms (...)
    crypto_alg = crypto_algs[ike['crypto-alg']]
    integ_alg = integ_algs[ike['integ-alg']]
    dh_group = dh_type_algs[ike['dh-group']]
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_ike_transforms"
    cmd['cmd']['params']    = { 'name':name, 'crypto_alg':crypto_alg, 'crypto_key_size':ike['key-size'], 'integ_alg':integ_alg, 'dh_group':dh_group }
    cmd['cmd']['descr']     = "set IKEv2 crypto algorithms, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_esp_transforms (...)
    crypto_alg = crypto_algs[esp['crypto-alg']]
    integ_alg = integ_algs[esp['integ-alg']]
    dh_group = dh_type_algs[esp['dh-group']]
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_esp_transforms"
    cmd['cmd']['params']    = { 'name':name, 'crypto_alg':crypto_alg, 'crypto_key_size':esp['key-size'], 'integ_alg':integ_alg, 'dh_group':dh_group }
    cmd['cmd']['descr']     = "set IKEv2 ESP crypto algorithms, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_sa_lifetime (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_sa_lifetime"
    cmd['cmd']['params']    = { 'name':name, 'lifetime':lifetime, 'lifetime_jitter':10, 'handover':5, 'lifetime_maxdata':0 }
    cmd['cmd']['descr']     = "set IKEv2 connection lifetime, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_initiate_sa_init (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_initiate_sa_init"
    cmd['cmd']['params']    = { 'name':name }
    cmd['cmd']['descr']     = "initialize IKEv2 connection, profile %s" % name
    cmd_list.append(cmd)

def _add_loop0_bridge_l2gre_ipsec(cmd_list, params, l2gre_tunnel_ips, bridge_id):
    """Add GRE tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param l2gre_tunnel_ips:    GRE tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.

    :returns: None.
    """
    local_sa_id = generate_sa_id()
    _add_ipsec_sa(cmd_list, params['ipsec']['local-sa'], local_sa_id)
    remote_sa_id = generate_sa_id()
    _add_ipsec_sa(cmd_list, params['ipsec']['remote-sa'], remote_sa_id)

    _add_loopback(
                cmd_list,
                'loop0_sw_if_index',
                params['loopback-iface'],
                id=bridge_id)
    _add_bridge(
                cmd_list, bridge_id)
    _add_gre_tunnel(
                cmd_list,
                'gre_tunnel_sw_if_index',
                l2gre_tunnel_ips['src'],
                l2gre_tunnel_ips['dst'],
                local_sa_id,
                remote_sa_id)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='loop0_' + params['loopback-iface']['addr'],
                bridge_id=bridge_id,
                bvi=1,
                shg=0,
                cache_key='loop0_sw_if_index')
    _add_interface_to_bridge(
                cmd_list,
                iface_description='l2gre_tunnel',
                bridge_id=bridge_id,
                bvi=0,
                shg=1,
                cache_key='gre_tunnel_sw_if_index')

def _add_loop0_bridge_l2gre_ikev2(cmd_list, params, l2gre_tunnel_ips, bridge_id):
    """Add IKEv2 tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param l2gre_tunnel_ips:    GRE tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.

    :returns: None.
    """
    _add_loopback(
                cmd_list,
                'loop0_sw_if_index',
                params['loopback-iface'],
                id=bridge_id)
    _add_bridge(
                cmd_list, bridge_id)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='loop0_' + params['loopback-iface']['addr'],
                bridge_id=bridge_id,
                bvi=1,
                shg=0,
                cache_key='loop0_sw_if_index')

    src = str(IPNetwork(l2gre_tunnel_ips['src']).ip)
    ikev2_profile_name = 'pr' + str(params['tunnel-id'])
    _add_ikev2_common_profile(
                      cmd_list, ikev2_profile_name, params['tunnel-id'],
                      params['ikev2']['remote-device-id'],
                      params['ikev2']['certificate'],
                      bridge_id, src)

    if params['ikev2']['role'] == 'initiator':
        dst = ipaddress.ip_address(IPNetwork(l2gre_tunnel_ips['dst']).ip)
        _add_ikev2_initiator_profile(
                        cmd_list,
                        ikev2_profile_name, params['ikev2']['lifetime'],
                        'loop1_sw_if_index',
                        dst,
                        params['ikev2']['ike'],
                        params['ikev2']['esp']
                        )

def _add_loop1_bridge_vxlan(cmd_list, params, loop1_cfg, remote_loop1_cfg, l2gre_tunnel_ips, bridge_id):
    """Add VxLAN tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param loop1_ip:            Loopback ip address.
    :param loop1_mac:           Loopback MAC address.
    :param l2gre_tunnel_ips:    VxLAN tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.

    :returns: None.
    """
    _add_loopback(
                cmd_list,
                'loop1_sw_if_index',
                loop1_cfg,
                id=bridge_id,
                internal=True)
    _add_bridge(
                cmd_list, bridge_id)
    _add_vxlan_tunnel(
                cmd_list,
                'vxlan_tunnel_sw_if_index',
                bridge_id,
                l2gre_tunnel_ips['src'],
                l2gre_tunnel_ips['dst'],
                params)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='loop1_' + loop1_cfg['addr'],
                bridge_id=bridge_id,
                bvi=1,
                shg=0,
                cache_key='loop1_sw_if_index')
    _add_interface_to_bridge(
                cmd_list,
                iface_description='vxlan_tunnel',
                bridge_id=bridge_id,
                bvi=0,
                shg=1,
                cache_key='vxlan_tunnel_sw_if_index')

    # Configure static ARP for remote loop1 IP.
    # loop1-s are not managed by Linux, so Linux can't answer them.
	# Short the circuit and don't send ARP requests on network.
	# Note we use global ARP cache and not bridge private ARP cache,
	# as the ARP responses generated by bridge has no impact on local site.
	# The bridge can send them back on the network if ARP request was received
	# on network. But it can't send them to previous nodes,
	# if the request were generated by them.
    remote_loop1_ip  = remote_loop1_cfg['addr'].split('/')[0]  # Remove length of address
    remote_loop1_mac = remote_loop1_cfg['mac']
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['descr']   = "add static arp entry %s %s" % (remote_loop1_ip, remote_loop1_mac)
    cmd['cmd']['params']  = ["sudo vppctl set ip neighbor loop%d %s %s static" % (bridge_id, remote_loop1_ip, remote_loop1_mac)]
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "delete static arp entry %s %s" % (remote_loop1_ip, remote_loop1_mac)
    cmd['revert']['params'] = ["sudo vppctl set ip neighbor del loop%d %s %s static" % (bridge_id, remote_loop1_ip, remote_loop1_mac)]
    cmd_list.append(cmd)


def add_tunnel(params):
    """Generate commands to add IPSEC-GRE and VxLAN tunnels into VPP.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []

    encryption_mode = params.get("encryption-mode", "static")

    loop0_ip  = IPNetwork(params['loopback-iface']['addr'])     # 10.100.0.4 / 10.100.0.5
    loop0_mac = EUI(params['loopback-iface']['mac'], dialect=mac_unix_expanded) # 02:00:27:fd:00:04 / 02:00:27:fd:00:05

    loop1_ip         = copy.deepcopy(loop0_ip)
    loop1_ip.value  += IPAddress('0.1.0.0').value               # 10.100.0.4 -> 10.101.0.4 / 10.100.0.5 -> 10.101.0.5
    loop1_mac        = copy.deepcopy(loop0_mac)
    loop1_mac.value += EUI('00:00:00:01:00:00').value           # 02:00:27:fd:00:04 -> 02:00:27:fe:00:04 / 02:00:27:fd:00:05 -> 02:00:27:fe:00:05

    remote_loop1_ip         = copy.deepcopy(loop1_ip)
    remote_loop1_ip.value  ^= IPAddress('0.0.0.1').value        # 10.101.0.4 -> 10.101.0.5 / 10.101.0.5 -> 10.101.0.4
    remote_loop1_mac        = copy.deepcopy(loop1_mac)
    remote_loop1_mac.value ^= EUI('00:00:00:00:00:01').value    # 02:00:27:fe:00:04 -> 02:00:27:fe:00:05 / 02:00:27:fe:00:05 -> 02:00:27:fe:00:04

    # Add loop1-bridge-vxlan
    vxlan_ips = {'src':params['src'], 'dst':params['dst']}
    loop1_cfg = {'addr':str(loop1_ip), 'mac':str(loop1_mac), 'mtu': 9000}
    remote_loop1_cfg = {'addr':str(remote_loop1_ip), 'mac':str(remote_loop1_mac)}
    _add_loop1_bridge_vxlan(cmd_list, params, loop1_cfg, remote_loop1_cfg, vxlan_ips, bridge_id=(params['tunnel-id']*2+1))

    l2gre_ips = {'src':str(loop1_ip), 'dst':str(remote_loop1_ip)}
    if encryption_mode == "static":
        # Add loop0-bridge-l2gre-ipsec
        _add_loop0_bridge_l2gre_ipsec(cmd_list, params, l2gre_ips, bridge_id=params['tunnel-id']*2)
    elif encryption_mode == "ikev2":
        # Add loop0-bridge-l2gre-ikev2
        _add_loop0_bridge_l2gre_ikev2(cmd_list, params, l2gre_ips, params['tunnel-id']*2)

    # --------------------------------------------------------------------------
    # Add following section to frr ospfd.conf
    #           !
    #               interface <tap of loopback iface>
    #                 ip ospf network point-to-point
    #           !
    # Add following line into 'router ospf' section of ospfd.conf
    #           network <loopback ip> area 0.0.0.0
    # Restart frr
    # --------------------------------------------------------------------------
    if 'routing' in params['loopback-iface'] and params['loopback-iface']['routing'] == 'ospf':
        ospfd_file = fwglobals.g.FRR_OSPFD_FILE

        # Create /etc/frr/ospfd.conf file if it does not exist yet
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "python"
        cmd['cmd']['descr']     = "create ospfd file if needed"
        cmd['cmd']['params']    = {
                                    'module': 'fwutils',
                                    'func':   'frr_create_ospfd',
                                    'args': {
                                        'frr_cfg_file':     fwglobals.g.FRR_CONFIG_FILE,
                                        'ospfd_cfg_file':   ospfd_file,
                                        'router_id':        params['loopback-iface']['addr'].split('/')[0]   # Get rid of address length
                                    }
                                  }
        # Don't delete /etc/frr/ospfd.conf on revert, as it might be used by other interfaces too
        cmd_list.append(cmd)

        # Add point-to-point type of interface for the tunnel address
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   = "add loopback interface %s to ospf as point-to-point" % params['loopback-iface']['addr']
        cmd['cmd']['params']  = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':'loop0_sw_if_index'} ]},
            'if [ -z "$(grep \'interface DEV-STUB\' %s)" ]; then sudo printf "' % ospfd_file + \
            'interface DEV-STUB\n' + \
            '    ip ospf network point-to-point\n' + \
            '!\n' + \
            '" >> %s; fi' % ospfd_file]
        cmd['revert'] = {}
        cmd['revert']['name']    = "exec"
        cmd['revert']['descr']   = "remove loopback interface %s from ospf as point-to-point" % params['loopback-iface']['addr']
        cmd['revert']['params']  = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':'loop0_sw_if_index'} ]},
            'sed -i -E "/interface DEV-STUB/,+2d" %s; sudo systemctl restart frr' % ospfd_file ]
        cmd['revert']['filter']  = 'must'   # When 'remove-XXX' commands are generated out of the 'add-XXX' commands, run this command even if vpp doesn't run
        cmd_list.append(cmd)

        # Add network for the tunnel interface.
        addr = params['loopback-iface']['addr']  # Escape slash in address with length to prevent sed confusing
        addr = addr.split('/')[0] + r"\/" + addr.split('/')[1]

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   = "add loopback interface %s to ospf" % params['loopback-iface']['addr']
        cmd['cmd']['params']  = [
            'if [ -z "$(grep \'network %s\' %s)" ]; then sed -i -E "s/([ ]+)(ospf router-id .*)/\\1\\2\\n\\1network %s area 0.0.0.0/" %s; fi' %
            (addr , ospfd_file , addr , ospfd_file) ]
        cmd['revert'] = {}
        cmd['revert']['name']    = "exec"
        cmd['revert']['descr']   = "remove loopback interface %s from ospf" % params['loopback-iface']['addr']
        cmd['revert']['params']  = [
            'sed -i -E "/[ ]+network %s area 0.0.0.0.*/d" %s; sudo systemctl restart frr' % (addr , ospfd_file) ]
        cmd['revert']['filter']  = 'must'   # When 'remove-XXX' commands are generated out of the 'add-XXX' commands, run this command even if vpp doesn't run
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = 'exec'
        cmd['cmd']['params']  = [ 'sudo systemctl restart frr; if [ -z "$(pgrep frr)" ]; then exit 1; fi' ]
        cmd['cmd']['descr']   = "restart frr"
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "preprocess tunnel add"
        cmd['cmd']['params']  = {
                        'module': 'fwutils',
                        'func'  : 'tunnel_change_postprocess',
                        'args'  : { 'add': True, 'addr': params['loopback-iface']['addr']},
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "preprocess tunnel remove"
        cmd['revert']['params'] = {
                        'module': 'fwutils',
                        'func'  : 'tunnel_change_postprocess',
                        'args'  : { 'add': False, 'addr': params['loopback-iface']['addr']},
        }
        cmd_list.append(cmd)

    return cmd_list

def modify_tunnel(params):
    remote_device_id = str(params['ikev2']['remote-device-id']),
    certificate = params['ikev2']['certificate']
    cmd_list = []
    # Add public certificate file
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "add IKEv2 public certificate for %s" % remote_device_id
    cmd['cmd']['params']    = {
                                'module': 'fwutils',
                                'func'  : 'ikev2_add_public_certificate',
                                'args'  : {'device_id': 'test', 'certificate': certificate}
                                }
    cmd_list.append(cmd)
    return cmd_list

def get_request_key(params):
    """Get add-tunnel command.

    :param params:        Parameters from flexiManage.

    :returns: add-tunnel command.
    """
    key = 'add-tunnel:%s' % (params['tunnel-id'])
    return key
