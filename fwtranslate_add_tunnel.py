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

import copy
import ipaddress
import os

import fwikev2
import fwutils
import fwglobals
import socket

from netaddr import *

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

def validate_tunnel_id(tunnel_id):
    bridge_id = tunnel_id*2+1 # each tunnel uses two bridges - one with id=tunnel_id*2 and one with id=tunnel_id*2+1
    min, max = fwglobals.g.LOOPBACK_ID_TUNNELS
    if min <= bridge_id <= max:
        return (True, None)
    return (False,
        "tunnel_id %d can't be served due to out of available bridge id-s" % (tunnel_id))

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
    mac  = iface_params.get('mac', None)
    mtu  = iface_params['mtu']

    # ret_attr  - attribute of the object returned by command,
    #             value of which is stored in cache to be available
    #             for next commands.
    # cache_key - key in cache, where the value
    #             of the 'ret_attr' attribute is stored.
    ret_attr = 'sw_if_index'
    mac_bytes = 0
    if mac:
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
    cmd['cmd']['params']    = { 'bd_id':bridge_id , 'is_add':1, 'learn':1, 'forward':1, 'uu_flood':1, 'flood':1, 'arp_term':0 }
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

def _add_gre_tunnel(cmd_list, cache_key, src, dst, local_sa_id = None, remote_sa_id = None, up = True):
    """Add GRE tunnel command into the list.

    :param cmd_list:             List of commands.
    :param cache_key:            Cache key of the tunnel to be used by others.
    :param src:                  Source ip address.
    :param dst:                  Destination ip address.
    :param local_sa_id:          Local SA identifier.
    :param remote_sa_id:         Remote SA identifier.
    :param up:                   Interface state is UP/DOWN.

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

    if local_sa_id and remote_sa_id:
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

    if up:
        # interface.api.json: sw_interface_set_flags (..., sw_if_index, flags, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "sw_interface_set_flags"
        cmd['cmd']['descr']   = "UP GRE tunnel %s -> %s" % (src, dst)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                  'flags':1 # VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP
                                }
        cmd_list.append(cmd)

def _add_ipip_tunnel(cmd_list, cache_key, src, dst, addr, instance):
    """Add IPIP tunnel command into the list.

    :param cmd_list:             List of commands.
    :param cache_key:            Cache key of the tunnel to be used by others.
    :param src:                  Source ip address.
    :param dst:                  Destination ip address.
    :param addr:                 Interface ip address.
    :param instance:             Tunnel instance number.

    :returns: None.
    """
    # ipip.api.json: ipip_add_tunnel (tunnel <type vl_api_ipip_tunnel_t>)
    tunnel = {
        'src': ipaddress.ip_address(src),
        'dst': ipaddress.ip_address(dst),
        'instance': instance
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "ipip_add_tunnel"
    cmd['cmd']['params']        = {'tunnel': tunnel}
    cmd['cmd']['cache_ret_val'] = ('sw_if_index', cache_key)
    cmd['cmd']['descr']         = "create ipip tunnel %s -> %s" % (src, dst)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'ipip_del_tunnel'
    cmd['revert']['params']     = {'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ]}
    cmd['revert']['descr']      = "delete ipip tunnel %s -> %s" % (src, dst)
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "sw_interface_add_del_address"
    cmd['cmd']['descr']     = "set %s to tunnel interface" % addr
    cmd['cmd']['params']    = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                'is_add':1, 'prefix':addr }
    cmd['revert'] = {}
    cmd['revert']['name']   = "sw_interface_add_del_address"
    cmd['revert']['descr']  = "unset %s from tunnel interface" % addr
    cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ],
                                'is_add':0, 'prefix':addr }
    cmd_list.append(cmd)

def _add_vxlan_tunnel(cmd_list, cache_key, dev_id, bridge_id, src, dst, params):
    """Add VxLAN tunnel command into the list.

    :param cmd_list:             List of commands.
    :param cache_key:            Cache key of the tunnel to be used by others.
    :param dev_id:               Interface bus address to create tunnel for.
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

    # for lte interface, we need to get the current source IP, and not the one stored in DB. The IP may have changed due last 'add-interface' job.
    if fwutils.is_lte_interface_by_dev_id(dev_id):
        tap_name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True)
        if tap_name:
            source = fwutils.get_interface_address(tap_name)
            if source:
                src = source.split('/')[0]
                src_addr = ipaddress.ip_address(src)

    cmd_params = {
            'is_add'               : 1,
            'src_address'          : src_addr,
            'dst_address'          : dst_addr,
            'vni'                  : bridge_id,
            'dest_port'            : int(params.get('dstPort', 4789)),
            'substs': [{'add_param': 'next_hop_sw_if_index', 'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': params['dev_id']},
                       {'add_param': 'next_hop_ip', 'val_by_func': 'get_tunnel_gateway', 'arg': [dst, dev_id]}],
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

def _add_ikev2_common_profile(cmd_list, params, name, cache_key, auth_method, local_fqdn, remote_fqdn):
    """Add IKEv2 common profile commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param name:                Profile name.
    :param cache_key:           Tunnel interface cache_key.
    :param auth_method:         Authenticate method, i.e. IKEV2_AUTH_METHOD_RSA_SIG(1) or IKEV2_AUTH_METHOD_SHARED_KEY_MIC(2)
    :param local_fqdn:          Local FQDN stands for local domain name.
    :param remote_fqdn:         Remote FQDN stands for remote domain name.

    :returns: None.
    """
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


    # ikev2.api.json: ikev2_set_tunnel_interface (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_tunnel_interface"
    cmd['cmd']['params']    = { 'name':name , 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':cache_key} ], }
    cmd['cmd']['descr']     = "set tunnel interface for IKEv2 profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_auth (..., auth_method)
    auth_data = ''
    if auth_method == 1:
        auth_data = fwglobals.g.ikev2.remote_certificate_filename_get(params['ikev2']['remote-device-id']).encode()
    if auth_method == 2:
        auth_data = params['ikev2']['psk'].encode()

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_auth"
    cmd['cmd']['params']    = { 'name':name, 'auth_method':auth_method, 'data':auth_data, 'data_len':len(auth_data) }
    cmd['cmd']['descr']     = "set IKEv2 auth method, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_id (..., 'is_local':1)
    id_type = 2 # IKEV2_ID_TYPE_ID_FQDN
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_id"
    cmd['cmd']['params']    = { 'name':name, 'is_local':1, 'id_type':id_type, 'data':local_fqdn.encode(), 'data_len':len(local_fqdn) }
    cmd['cmd']['descr']     = "set IKEv2 local id, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_id (..., 'is_local':0)
    id_type = 2 # IKEV2_ID_TYPE_ID_FQDN
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_id"
    cmd['cmd']['params']    = { 'name':name, 'is_local':0, 'id_type':id_type, 'data':remote_fqdn.encode(), 'data_len':len(remote_fqdn) }
    cmd['cmd']['descr']     = "set IKEv2 local id, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_ts (..., 'is_local':1)
    local_ts = {'is_local'    : 1,
                'protocol_id' : 0,
                'start_port'  : 0,
                'end_port'    : 65535,
                'start_addr'  : ipaddress.ip_address('0.0.0.0'),
                'end_addr'    : ipaddress.ip_address('255.255.255.255')}

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_ts"
    cmd['cmd']['params']    = { 'name':name, 'ts':local_ts }
    cmd['cmd']['descr']     = "set IKEv2 local traffic selector, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_profile_set_ts (..., 'is_local':0)
    remote_ts = {'is_local'    : 0,
                 'protocol_id' : 0,
                 'start_port'  : 0,
                 'end_port'    : 65535,
                 'start_addr'  : ipaddress.ip_address('0.0.0.0'),
                 'end_addr'    : ipaddress.ip_address('255.255.255.255')}

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_profile_set_ts"
    cmd['cmd']['params']    = { 'name':name, 'ts':remote_ts }
    cmd['cmd']['descr']     = "set IKEv2 remote traffic selector, profile %s" % name
    cmd_list.append(cmd)

def _add_ikev2_certificates(cmd_list, remote_device_id, certificate):
    """Add IKEv2 certificate commands into the list.

    :param cmd_list:            List of commands.
    :param remote_device_id:    Remote device id.
    :param certificate:         Remote device public certificate.

    :returns: None.
    """
    machine_id = fwutils.get_machine_id()

    # ikev2.api.json: ikev2_set_local_key (...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_local_key"
    cmd['cmd']['params']    = { 'key_file':fwglobals.g.ikev2.IKEV2_PRIVATE_KEY_FILE }
    cmd['cmd']['descr']     = "set IKEv2 local key"
    cmd_list.append(cmd)

    # Add public certificate file
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "add IKEv2 public certificate for %s" % remote_device_id
    cmd['cmd']['params']    = {
                                'object': 'fwglobals.g.ikev2',
                                'func'  : 'add_public_certificate',
                                'args'  : {'device_id': remote_device_id, 'certificate': certificate}
                                }
    cmd_list.append(cmd)

def _add_ikev2_initiator_profile(cmd_list, name, lifetime,
                                 responder_cache_key,
                                 responder_address,
                                 responder_dev_id,
                                 ike, esp):
    """Add IKEv2 initiator profile commands into the list.

    :param cmd_list:            List of commands.
    :param name:                Profile name.
    :param lifetime:            Connection life time.
    :param responder_cache_key: Interface with responder.
    :param responder_address:   Responder IP address.
    :param responder_dev_id:    Responder device id.
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

    if responder_cache_key:
        # ikev2.api.json: ikev2_set_responder (...)
        responder = {
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_key':responder_cache_key} ],
                    'addr':ipaddress.ip_address(responder_address)
        }
    else:
        # ikev2.api.json: ikev2_set_responder (...)
        responder = {
                    'substs': [{'add_param': 'sw_if_index', 'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': responder_dev_id}],
                    'addr':ipaddress.ip_address(responder_address)
        }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_responder"
    cmd['cmd']['params']    = { 'name':name, 'responder':responder }
    cmd['cmd']['descr']     = "set IKEv2 responder, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_ike_transforms (...)
    ike_tr = {
              'crypto_alg'      : crypto_algs[ike['crypto-alg']],
              'crypto_key_size' : ike['key-size'],
              'integ_alg'       : integ_algs[ike['integ-alg']],
              'dh_group'        : dh_type_algs[ike['dh-group']]
             }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_ike_transforms"
    cmd['cmd']['params']    = { 'name':name, 'tr':ike_tr }
    cmd['cmd']['descr']     = "set IKEv2 crypto algorithms, profile %s" % name
    cmd_list.append(cmd)

    # ikev2.api.json: ikev2_set_esp_transforms (...)
    esp_tr = {
              'crypto_alg'      : crypto_algs[esp['crypto-alg']],
              'crypto_key_size' : esp['key-size'],
              'integ_alg'       : integ_algs[esp['integ-alg']],
              'dh_group'        : dh_type_algs[esp['dh-group']]
             }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "ikev2_set_esp_transforms"
    cmd['cmd']['params']    = { 'name':name, 'tr':esp_tr }
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

def _add_loop_bridge_l2gre_ipsec(cmd_list, params, l2gre_tunnel_ips, bridge_id, loop_cache_key):
    """Add GRE tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param l2gre_tunnel_ips:    GRE tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.
    :param loop_cache_key:      Loopback cache key.

    :returns: None.
    """
    local_sa_id = generate_sa_id()
    _add_ipsec_sa(cmd_list, params['ipsec']['local-sa'], local_sa_id)
    remote_sa_id = generate_sa_id()
    _add_ipsec_sa(cmd_list, params['ipsec']['remote-sa'], remote_sa_id)

    _add_loopback(
                cmd_list,
                loop_cache_key,
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
                cache_key=loop_cache_key)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='l2gre_tunnel',
                bridge_id=bridge_id,
                bvi=0,
                shg=1,
                cache_key='gre_tunnel_sw_if_index')

def _add_ikev2(cmd_list, params, responder_ip_address, tunnel_intf_cache_key, auth_method, responder_cache_key):
    """Add IKEv2 tunnel, loopback and bridge commands into the list.

    :param cmd_list:                List of commands.
    :param params:                  Parameters from flexiManage.
    :param responder_address:       Responder IP address.
    :param tunnel_intf_cache_key:   Tunnel interface cache key.
    :param auth_method:             Authenticate method.
    :param responder_cache_key:     Responder interface cache key.

    :returns: None.
    """
    local_fqdn = ''
    remote_fqdn = ''

    if 'certificate' in params['ikev2']:
        local_fqdn = fwutils.get_machine_id() + '-' + str(params['tunnel-id'])
        remote_fqdn = params['ikev2']['remote-device-id'] + '-' + str(params['tunnel-id'])
        _add_ikev2_certificates(
                cmd_list,
                params['ikev2']['remote-device-id'],
                params['ikev2']['certificate'])
    else:
        local_fqdn = params['ikev2']['local-device-id']
        remote_fqdn = params['ikev2']['remote-device-id']

    ikev2_profile_name = fwglobals.g.ikev2.profile_name_get(params['tunnel-id'])
    _add_ikev2_common_profile(
                      cmd_list,
                      params,
                      ikev2_profile_name,
                      tunnel_intf_cache_key,
                      auth_method,
                      local_fqdn,
                      remote_fqdn)

    if params['ikev2']['role'] == 'initiator':
        _add_ikev2_initiator_profile(
                        cmd_list,
                        ikev2_profile_name,
                        params['ikev2']['lifetime'],
                        responder_cache_key,
                        responder_ip_address,
                        params['dev_id'],
                        params['ikev2']['ike'],
                        params['ikev2']['esp']
                        )

def _add_loop_bridge_l2gre_ikev2(cmd_list, params, l2gre_tunnel_ips, bridge_id, loop0_cache_key, loop1_cache_key):
    """Add IKEv2 tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param l2gre_tunnel_ips:    GRE tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.
    :param loop0_cache_key:     Loop0 cache key.
    :param loop1_cache_key:     Loop1 cache key.

    :returns: None.
    """
    _add_loopback(
                cmd_list,
                loop0_cache_key,
                params['loopback-iface'],
                id=bridge_id)
    _add_bridge(
                cmd_list, bridge_id)
    _add_gre_tunnel(
                cmd_list,
                'gre_tunnel_sw_if_index',
                l2gre_tunnel_ips['src'],
                l2gre_tunnel_ips['dst'],
                up = False)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='loop0_' + params['loopback-iface']['addr'],
                bridge_id=bridge_id,
                bvi=1,
                shg=0,
                cache_key=loop0_cache_key)
    gre_tunnel_sw_if_index = 'gre_tunnel_sw_if_index'
    _add_interface_to_bridge(
                cmd_list,
                iface_description='l2gre_tunnel',
                bridge_id=bridge_id,
                bvi=0,
                shg=1,
                cache_key=gre_tunnel_sw_if_index)

    responder_ip_address = str(IPNetwork(l2gre_tunnel_ips['dst']).ip)
    auth_method = 1 # IKEV2_AUTH_METHOD_RSA_SIG
    _add_ikev2(cmd_list, params, responder_ip_address, gre_tunnel_sw_if_index, auth_method, loop1_cache_key)

def _add_loop0_bridge_l2gre(cmd_list, params, l2gre_tunnel_ips, bridge_id):
    """Add unprotected tunnel, loopback and bridge commands into the list.

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
    _add_gre_tunnel(
                cmd_list,
                'gre_tunnel_sw_if_index',
                l2gre_tunnel_ips['src'],
                l2gre_tunnel_ips['dst'])
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

def _add_loop_bridge_vxlan(cmd_list, params, loop_cfg, remote_loop_cfg, vxlan_ips, bridge_id, internal, loop_cache_key):
    """Add VxLAN tunnel, loopback and bridge commands into the list.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param loop_cfg:            Local loopback config.
    :param remote_loop_cfg:     Remote loopback config.
    :param vxlan_ips:           VxLAN tunnel src and dst ip addresses.
    :param bridge_id:           Bridge identifier.
    :param internal:            Hide loopback from Linux.
    :param loop_cache_key:      Loopback cache key.

    :returns: None.
    """
    loop_prefix='loop%u_' % bridge_id

    _add_loopback(
                cmd_list,
                loop_cache_key,
                loop_cfg,
                id=bridge_id,
                internal=internal)
    _add_bridge(
                cmd_list, bridge_id)
    _add_vxlan_tunnel(
                cmd_list,
                'vxlan_tunnel_sw_if_index',
                params.get('dev_id'),
                bridge_id,
                vxlan_ips['src'],
                vxlan_ips['dst'],
                params)
    _add_interface_to_bridge(
                cmd_list,
                iface_description=loop_prefix + loop_cfg['addr'],
                bridge_id=bridge_id,
                bvi=1,
                shg=0,
                cache_key=loop_cache_key)
    _add_interface_to_bridge(
                cmd_list,
                iface_description='vxlan_tunnel',
                bridge_id=bridge_id,
                bvi=0,
                shg=1,
                cache_key='vxlan_tunnel_sw_if_index')

    if internal:
        # Configure static ARP for remote loop IP.
        # loop-s are not managed by Linux, so Linux can't answer them.
        # Short the circuit and don't send ARP requests on network.
        # Note we use global ARP cache and not bridge private ARP cache,
        # as the ARP responses generated by bridge has no impact on local site.
        # The bridge can send them back on the network if ARP request was received
        # on network. But it can't send them to previous nodes,
        # if the request were generated by them.
        remote_loop_ip  = remote_loop_cfg['addr'].split('/')[0]  # Remove length of address
        remote_loop_mac = remote_loop_cfg['mac']

        # ip_neighbor.api.json: _vl_api_ip_neighbor (...)
        # 
        # Available flags:
        #    IP_API_NEIGHBOR_FLAG_NONE         IPNeighborFlags = 0
	    #    IP_API_NEIGHBOR_FLAG_STATIC       IPNeighborFlags = 1
	    #    IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY IPNeighborFlags = 2
        neighbor = {
            'substs':       [ { 'add_param':'sw_if_index', 'val_by_key':loop_cache_key} ],
            'flags'         : 1,
            'mac_address'   : remote_loop_mac,
            'ip_address'    : remote_loop_ip
        }

        # ip_neighbor.api.json: ip_neighbor_add_del (...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "ip_neighbor_add_del"
        cmd['cmd']['params']    = { 'neighbor': neighbor, 'is_add':1 }
        cmd['cmd']['descr']     = "add static arp entry %s %s" % (remote_loop_ip, remote_loop_mac)
        cmd['revert'] = {}
        cmd['revert']['name']   = 'ip_neighbor_add_del'
        cmd['revert']['params'] = { 'neighbor': neighbor, 'is_add':0 }
        cmd['revert']['descr']  = "delete static arp entry %s %s" % (remote_loop_ip, remote_loop_mac)
        cmd_list.append(cmd)



def _add_peer(cmd_list, params, tunnel_cache_key, peer_loopback_cache_key):
    """Add tunnel for a peer.

    :param cmd_list:            List of commands.
    :param params:              Parameters from flexiManage.
    :param tunnel_cache_key:    Tunnel cache key.

    :returns: None.
    """
    auth_method      = 2 # IKEV2_AUTH_METHOD_SHARED_KEY_MIC
    mtu              = params['peer']['mtu']
    addr             = params['peer']['addr']
    tunnel_addr      = fwutils.build_second_loop_ip_address(addr)
    iface_params     = params['peer']
    next_hop         = str(IPNetwork(addr).ip ^ IPAddress("0.0.0.1"))
    id               = params['tunnel-id']*2

    _add_ipip_tunnel(cmd_list, tunnel_cache_key, params['src'], params['dst'], tunnel_addr, id)

    loopback_params = {'addr':addr, 'mtu': mtu}
    _add_loopback(cmd_list, peer_loopback_cache_key, loopback_params, id=id)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add interface mapping"
    cmd['cmd']['params']  = {
                    'substs': [ { 'add_param':'src_sw_if_index', 'val_by_key':peer_loopback_cache_key},
                                { 'add_param':'dst_sw_if_index', 'val_by_key':tunnel_cache_key} ],
                    'module': 'fwutils',
                    'func'  : 'vpp_tap_inject_map_interface',
                    'args'  : {'is_add':1}
    }
    cmd['revert'] = {}
    cmd['revert']['name']    = "python"
    cmd['revert']['descr']   = "remove interface mapping"
    cmd['revert']['params']  = {
                    'substs': [ { 'add_param':'src_sw_if_index', 'val_by_key':peer_loopback_cache_key},
                                { 'add_param':'dst_sw_if_index', 'val_by_key':tunnel_cache_key} ],
                    'module': 'fwutils',
                    'func'  : 'vpp_tap_inject_map_interface',
                    'args'  : {'is_add':0}
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add l3xc connection"
    cmd['cmd']['params']  = {
                    'substs': [ { 'add_param':'src_sw_if_index', 'val_by_key':peer_loopback_cache_key},
                                { 'add_param':'dst_sw_if_index', 'val_by_key':tunnel_cache_key} ],
                    'module': 'fwutils',
                    'func'  : 'vpp_l3xc_connect',
                    'args'  : {'is_add':1}
    }
    cmd['revert'] = {}
    cmd['revert']['name']    = "python"
    cmd['revert']['descr']   = "remove l3xc connection"
    cmd['revert']['params']  = {
                    'substs': [ { 'add_param':'src_sw_if_index', 'val_by_key':peer_loopback_cache_key},
                                { 'add_param':'dst_sw_if_index', 'val_by_key':tunnel_cache_key} ],
                    'module': 'fwutils',
                    'func'  : 'vpp_l3xc_connect',
                    'args'  : {'is_add':0}
    }
    cmd_list.append(cmd)

    # interface.api.json: sw_interface_set_mtu (..., sw_if_index, mtu, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "sw_interface_set_mtu"
    cmd['cmd']['descr']   = "set mtu=%s to ipip interface" % mtu
    cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_key':tunnel_cache_key} ],
                              'mtu': [ mtu , 0, 0, 0 ] }
    cmd_list.append(cmd)

    # interface.api.json: sw_interface_flexiwan_label_add_del (..., sw_if_index, n_labels, labels, ...)
    if 'multilink' in iface_params and 'labels' in iface_params['multilink']:
        labels = iface_params['multilink']['labels']
        if len(labels) > 0:
            # next_hop is a remote gateway
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "python"
            cmd['cmd']['descr']   = "add multilink labels into tunnel interface %s: %s" % (params['src'], labels)
            cmd['cmd']['params']  = {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_key':tunnel_cache_key} ],
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels': labels, 'next_hop': next_hop, 'remove': False }
            }
            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['descr']  = "remove multilink labels from tunnel interface %s: %s" % (params['src'], labels)
            cmd['revert']['params'] = {
                            'substs': [ { 'add_param':'sw_if_index', 'val_by_key':tunnel_cache_key} ],
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels': labels, 'next_hop': next_hop, 'remove': True }
            }
            cmd_list.append(cmd)

    _add_ikev2(cmd_list, params, params['dst'], tunnel_cache_key, auth_method, None)

def add_tunnel(params):
    """Generate commands to add tunnel into VPP.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    cmd_list = []
    loop0_ip = ''
    remote_loop0_ip = None

    encryption_mode = params.get("encryption-mode", "psk")

    if 'loopback-iface' in params:
        loop0_ip                = params['loopback-iface']['addr']
        remote_loop0_ip         = fwutils.build_remote_loop_ip_address(loop0_ip)       # 10.100.0.4 -> 10.100.0.5 / 10.100.0.5 -> 10.100.0.4

        loop0_mac               = EUI(params['loopback-iface']['mac'], dialect=mac_unix_expanded) # 02:00:27:fd:00:04 / 02:00:27:fd:00:05
        remote_loop0_mac        = copy.deepcopy(loop0_mac)
        remote_loop0_mac.value ^= EUI('00:00:00:00:00:01').value    # 02:00:27:fd:00:04 -> 02:00:27:fd:00:05 / 02:00:27:fd:00:05 -> 02:00:27:fd:00:04

        loop1_ip                = fwutils.build_second_loop_ip_address(loop0_ip)    # 10.100.0.4 -> 10.101.0.4 / 10.100.0.5 -> 10.101.0.5
        remote_loop1_ip         = fwutils.build_remote_loop_ip_address(loop1_ip)    # 10.101.0.4 -> 10.101.0.5 / 10.101.0.5 -> 10.101.0.4

        loop1_mac               = copy.deepcopy(loop0_mac)
        loop1_mac.value        += EUI('00:00:00:01:00:00').value           # 02:00:27:fd:00:04 -> 02:00:27:fe:00:04 / 02:00:27:fd:00:05 -> 02:00:27:fe:00:05
        remote_loop1_mac        = copy.deepcopy(loop1_mac)
        remote_loop1_mac.value ^= EUI('00:00:00:00:00:01').value    # 02:00:27:fe:00:04 -> 02:00:27:fe:00:05 / 02:00:27:fe:00:05 -> 02:00:27:fe:00:04

        # Add loop1-bridge-vxlan
        vxlan_ips = {'src':params['src'], 'dst':params['dst']}
        remote_loop0_cfg = {'addr':remote_loop0_ip, 'mac':str(remote_loop0_mac)}
        remote_loop1_cfg = {'addr':str(remote_loop1_ip), 'mac':str(remote_loop1_mac)}

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "python"
        cmd['cmd']['descr']     = "validate tunnel id"
        cmd['cmd']['params']    = {
                                    'module': 'fwtranslate_add_tunnel',
                                    'func':   'validate_tunnel_id',
                                    'args': {
                                        'tunnel_id': params['tunnel-id']
                                    }
                                }
        cmd_list.append(cmd)

    if 'peer' in params:
        tunnel_cache_key = 'ipip_tunnel_sw_if_index'
        peer_loopback_cache_key = 'peer_loopback_sw_if_index'
        _add_peer(cmd_list, params, tunnel_cache_key, peer_loopback_cache_key)
    else:
        if encryption_mode == "none":
            loop0_cfg = {'addr':str(loop0_ip), 'mac':str(loop0_mac), 'mtu': 9000}
            bridge_id = params['tunnel-id']*2
            _add_loop_bridge_vxlan(cmd_list, params, loop0_cfg, remote_loop0_cfg, vxlan_ips, bridge_id=bridge_id, internal=False, loop_cache_key='loop0_sw_if_index')
        else:
            loop1_cfg = {'addr':str(loop1_ip), 'mac':str(loop1_mac), 'mtu': 9000}
            bridge_id = params['tunnel-id']*2+1
            _add_loop_bridge_vxlan(cmd_list, params, loop1_cfg, remote_loop1_cfg, vxlan_ips, bridge_id=bridge_id, internal=True, loop_cache_key='loop1_sw_if_index')

            l2gre_ips = {'src':loop1_ip, 'dst':remote_loop1_ip}
            if encryption_mode == "psk":
                # Add loop0-bridge-l2gre-ipsec
                _add_loop_bridge_l2gre_ipsec(cmd_list, params, l2gre_ips, bridge_id=params['tunnel-id']*2, loop_cache_key='loop0_sw_if_index')
            elif encryption_mode == "ikev2":
                # Add loop0-bridge-l2gre-ikev2
                _add_loop_bridge_l2gre_ikev2(cmd_list, params, l2gre_ips, params['tunnel-id']*2, loop0_cache_key='loop0_sw_if_index', loop1_cache_key='loop1_sw_if_index')

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
    if 'loopback-iface' in params and 'routing' in params['loopback-iface'] and params['loopback-iface']['routing'] == 'ospf':

        # Add point-to-point type of interface for the tunnel address
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["interface DEV-STUB", "ip ospf network point-to-point"]
                },
                'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':'loop0_sw_if_index'} ]
        }
        cmd['cmd']['descr']   = "add loopback interface %s to ospf as point-to-point" % loop0_ip
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["interface DEV-STUB", "no ip ospf network point-to-point"]
                },
                'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func':'vpp_sw_if_index_to_tap', 'arg_by_key':'loop0_sw_if_index'} ]
        }
        cmd['revert']['descr']   = "remove loopback interface %s from ospf as point-to-point" % loop0_ip
        cmd_list.append(cmd)

        # Add network for the tunnel interface.
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "network %s area 0.0.0.0" % loop0_ip]
                }
        }
        cmd['cmd']['descr']   = "add loopback interface %s to ospf" % loop0_ip
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "no network %s area 0.0.0.0" % loop0_ip],

                    # Use 'wait_after' to ensure that redistributed routes that might be received over tunnel
                    # are removed from kernel and from vpp FIB
                    #
                    'wait_after': 2
                }
        }
        cmd['revert']['descr']   = "remove loopback interface %s from ospf" % loop0_ip
        cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "tunnel stats add"
    cmd['cmd']['params']  = {
                    'module': 'fwtunnel_stats',
                    'func'  : 'tunnel_stats_add',
                    'args'  : {'params': params}
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "tunnel stats remove"
    cmd['revert']['params'] = {
                    'module': 'fwtunnel_stats',
                    'func'  : 'tunnel_stats_remove',
                    'args'  : { 'tunnel_id': params['tunnel-id']}
    }
    cmd_list.append(cmd)

    policy_interface_cache_key = 'ipip_tunnel_sw_if_index' if 'peer' in params else 'loop0_sw_if_index'

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "postprocess add-tunnel"
    cmd['cmd']['params']  = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_add_tunnel_after',
                    'args'  : {'params':params},
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_key':policy_interface_cache_key} ]
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "preprocess remove-tunnel"
    cmd['revert']['params'] = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_remove_tunnel_before',
                    'args'  : {'params':params},
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_key':policy_interface_cache_key} ]
    }
    cmd_list.append(cmd)

    return cmd_list

def modify_tunnel(new_params, old_params):
    cmd_list = []

    remote_device_id = str(old_params['ikev2']['remote-device-id'])
    role = old_params['ikev2']['role']

    certificate = new_params['ikev2'].get('certificate', None)
    if certificate:
        # Add modify white list
        cmd = {}
        cmd['modify'] = 'modify'
        cmd['whitelist'] = {'certificate'}
        cmd_list.append(cmd)

        # Add public certificate file
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "python"
        cmd['cmd']['descr']     = "modify IKEv2 public certificate for %s" % remote_device_id
        cmd['cmd']['params']    = {
                                    'object': 'fwglobals.g.ikev2',
                                    'func'  : 'modify_certificate',
                                    'args'  : {'device_id'   : remote_device_id,
                                               'certificate' : certificate,
                                               'tunnel_id'   : new_params['tunnel-id']}
                                  }
        cmd_list.append(cmd)

    remote_cert_applied = new_params['ikev2'].get('remote-cert-applied', None)
    if remote_cert_applied:
        # Reinitiate IKEv2 session
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "python"
        cmd['cmd']['descr']     = "Reinitiate IKEv2 session with %s" % remote_device_id
        cmd['cmd']['params']    = {
                                    'object': 'fwglobals.g.ikev2',
                                    'func'  : 'reinitiate_session',
                                    'args'  : {'tunnel_id': new_params['tunnel-id'],
                                               'role'     : role}
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
