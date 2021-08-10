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

import fwglobals
import fwutils
import fw_nat_command_helpers

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
#
def add_interface(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']
    iface_addr = params.get('addr', '')
    iface_name = fwutils.dev_id_to_linux_if(dev_id)

    ######################################################################
    #  NO NEED TO SET IP AND UP/DOWN STATE IN VPP !
    #  WE DO THAT IN LINUX, TAP-INJECT REFLECTS THESE CHANGES TO VPP
    #  (as well we avoid various errors like 'duplicated address' on add
    #   or 'illegal addess' on delete ;))
    #  Note, as on Nov-2019 the opposite direction doesn't work,
    #  delete address in VPP doesn't delete it in Linux ?)
    ######################################################################

    # Add interface section into Netplan configuration file
    gw        = params.get('gateway', None)
    metric    = 0 if not params.get('metric', '') else int(params.get('metric', '0'))
    dhcp      = params.get('dhcp', 'no')
    int_type  = params.get('type', None)

    dnsServers  = params.get('dnsServers', [])
    # If for any reason, static IP interface comes without static dns servers, we set the default automatically
    if int_type == 'wan' and dhcp == 'no' and len(dnsServers) == 0:
        dnsServers = fwglobals.g.DEFAULT_DNS_SERVERS
    dnsDomains  = params.get('dnsDomains')

    mtu       = params.get('mtu', None)

    # To enable multiple LAN interfaces on the same subnet, we put them all into a bridge in VPP.
    # if interface needs to be inside a bridge, we indicate it with a 'bridge_addr' field of the 'add-interface' request.
    # In this case, we create in VPP a bridge (see fwtranslate_add_switch) with a loopback BVI interface.
    # Then, we put the IP address on the BVI interface. Therefore the physical interface should have no IP.
    # Then, we will also add this interface to the L2 bridge.
    bridge_addr   = params.get('bridge_addr')
    if bridge_addr:
        iface_addr = bridge_addr

    is_wifi = fwutils.is_wifi_interface_by_dev_id(dev_id)
    is_lte = fwutils.is_lte_interface_by_dev_id(dev_id) if not is_wifi else False
    is_non_dpdk = is_wifi or is_lte

    if is_non_dpdk:
        # Create tap interface in linux and vpp.
        # This command will create three interfaces:
        #   1. linux tap interface.
        #   2. vpp tap interface in vpp.
        #   3. linux interface for tap-inject.
        #
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   = "create tap interface in vpp and linux"
        cmd['cmd']['params']  = ["sudo vppctl create tap host-if-name %s" % fwutils.generate_linux_interface_short_name("tap", iface_name)]
        cmd['revert'] = {}
        cmd['revert']['name']    = "exec"
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-TAP', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]},
                                        "sudo vppctl delete tap sw_if_index DEV-TAP" ]
        cmd['revert']['descr']  = "delete tap interface in vpp and linux"
        cmd_list.append(cmd)

        if is_wifi:
            # Configure hostapd with saved configuration
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "python"
            cmd['cmd']['params'] = {
                    'module': 'fwutils',
                    'func': 'configure_hostapd',
                    'args': { 'dev_id': dev_id, 'configuration': params.get('configuration', None) }
            }
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "python"
            cmd['cmd']['params'] = {
                    'module': 'fwutils',
                    'func': 'start_hostapd'
            }
            cmd['cmd']['descr']  = "start hostpad"
            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func': 'stop_hostapd'
            }
            cmd['revert']['descr']  = "stop hostpad"
            cmd_list.append(cmd)

            bridge_name = fwutils.generate_linux_interface_short_name("br", iface_name)
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "exec"
            cmd['cmd']['params'] = [ "sudo brctl addbr %s || true" %  bridge_name ]
            cmd['cmd']['descr']  = "create linux bridge %s for interface %s" % (bridge_name, iface_name)

            cmd['revert'] = {}
            cmd['revert']['name']   = "exec"
            cmd['revert']['params'] = [ "sudo ip link set dev %s down && sudo brctl delbr %s" %  (bridge_name, bridge_name) ]
            cmd['revert']['descr']  = "remove linux bridge %s for interface %s" % (bridge_name, iface_name)
            cmd_list.append(cmd)

            # add tap into a bridge.
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "exec"
            cmd['cmd']['params'] =  [ {'substs': [ {'replace':'DEV-TAP', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]},
                                        "sudo brctl addif %s DEV-TAP || true" %  bridge_name ]
            cmd['cmd']['descr']  = "add tap interface of %s into the appropriate bridge %s" % (iface_name, bridge_name)

            cmd['revert'] = {}
            cmd['revert']['name']   = "exec"
            cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-TAP', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name } ]},
                                        "sudo brctl delif %s DEV-TAP" %  bridge_name ]
            cmd['revert']['descr']  = "remove tap from a bridge %s" % bridge_name
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "exec"
            cmd['cmd']['params'] =  [ "sudo brctl addif %s %s || true" %  (bridge_name, iface_name) ]
            cmd['cmd']['descr']  = "add wifi interface %s into the bridge %s" % (iface_name, bridge_name)

            cmd['revert'] = {}
            cmd['revert']['name']   = "exec"
            cmd['revert']['params'] = [ "sudo brctl delif %s %s" %  (bridge_name, iface_name) ]
            cmd['revert']['descr']  = "remove wifi interface %s from the bridge %s" %  (iface_name, bridge_name)
            cmd_list.append(cmd)

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']      = "exec"
            cmd['cmd']['descr']     = "UP bridge %s in Linux" % bridge_name
            cmd['cmd']['params']    = [ "sudo ip link set dev %s up" % bridge_name]
            cmd_list.append(cmd)
        elif is_lte:
            # dhcp for LTE interface has special meaning.
            # Although that flexiManage looks at it as DHCP because the user can't set static IP
            # but the agent looks at it as static IP from the modem.
            # We take the IP from the modem via the mbimcli command.
            # That's why we override the the 'dhcp' to 'no'
            #
            dhcp = 'no'

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']      = "exec"
            cmd['cmd']['descr']     = "UP interface %s in Linux" % iface_name
            cmd['cmd']['params']    = [ "sudo ip link set dev %s up" %  iface_name]
            cmd['revert'] = {}
            cmd['revert']['name']   = "exec"
            cmd['revert']['descr']  = "Down interface %s in Linux" % iface_name
            cmd['revert']['params'] = [ "sudo ip link set dev %s down && sudo ip addr flush dev %s" %  (iface_name, iface_name)]
            cmd_list.append(cmd)

            # connect the modem to the cellular provider
            configs = copy.deepcopy(params['configuration'])
            configs['dev_id'] = dev_id
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "python"
            cmd['cmd']['params'] = {
                        'module': 'fwutils',
                        'func': 'lte_connect',
                        'args': { 'params': configs }
            }
            cmd['cmd']['descr'] = "connect modem to lte cellular network provider"
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

    # add interface into netplan configuration
    netplan_params = {
        'module': 'fwnetplan',
        'func': 'add_remove_netplan_interface',
        'args': {   'is_add'   : 1,
                    'dev_id'   : dev_id,
                    'ip'       : iface_addr,
                    'gw'       : gw,
                    'metric'   : metric,
                    'dhcp'     : dhcp,
                    'type'     : int_type,
                    'mtu'      : mtu,
                    'dnsServers': dnsServers,
                    'dnsDomains': dnsDomains
        }
    }

    if is_lte:
        netplan_params['substs'] = [
            { 'add_param':'ip', 'val_by_func':'lte_get_ip_configuration', 'arg': [dev_id, 'ip'] },
            { 'add_param':'gw', 'val_by_func':'lte_get_ip_configuration', 'arg': [dev_id, 'gateway'] },
        ]

        # If a user doesn't configure static dns servers, we use the servers received from ISP
        if len(dnsServers) == 0:
            netplan_params['substs'].append({ 'add_param':'dnsServers', 'val_by_func':'lte_get_ip_configuration', 'arg': [dev_id, 'dns_servers'] })

    if bridge_addr:
        netplan_params['args']['ip'] = ''
        netplan_params['args']['validate_ip'] = False

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = netplan_params
    cmd['cmd']['descr'] = "add interface into netplan config file"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = copy.deepcopy(netplan_params)
    cmd['revert']['params']['args']['is_add'] = 0
    cmd['revert']['descr'] = "remove interface from netplan config file"
    cmd_list.append(cmd)

    if bridge_addr:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "sw_interface_set_l2_bridge"
        cmd['cmd']['descr']   = "add interface %s to bridge" % iface_name
        cmd['cmd']['params']  = {
            'substs': [
                { 'add_param':'rx_sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                { 'add_param':'bd_id', 'val_by_func': 'fwtranslate_add_switch.get_bridge_id', 'arg': bridge_addr }
            ],
            'enable':1, 'port_type':0
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = 'sw_interface_set_l2_bridge'
        cmd['revert']['descr']  = "remove interface %s from bridge" % iface_name
        cmd['revert']['params'] = {
            'substs': [
                { 'add_param':'rx_sw_if_index', 'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg':dev_id },
                { 'add_param':'bd_id', 'val_by_func': 'fwtranslate_add_switch.get_bridge_id', 'arg': bridge_addr }
            ],
            'enable':0
        }
        cmd_list.append(cmd)

        # set the bridge IP address here.
        # If the bridged interface exists in original netplan with set-name it might cause issues,
        # So we configure the IP address for the BVI interface here
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "set %s to BVI loopback interface in Linux" % bridge_addr
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'set_ip_on_bridge_bvi_interface',
            'args'  : {
                'is_add':      True,
                'bridge_addr': bridge_addr,
            }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "unset %s to BVI loopback interface in Linux" % bridge_addr
        cmd['revert']['params']  = {
            'module': 'fwutils',
            'func'  : 'set_ip_on_bridge_bvi_interface',
            'args'  : {
                'is_add':      False,
                'bridge_addr': bridge_addr,
            }
        }
        cmd_list.append(cmd)

    if mtu:
        # interface.api.json: sw_interface_set_mtu (..., sw_if_index, mtu, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "sw_interface_set_mtu"
        cmd['cmd']['descr']   = "set mtu=%s to interface" % (mtu)
        cmd['cmd']['params']  = {
            'substs':[{ 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
            'mtu': [ mtu , 0, 0, 0 ]
            }
        cmd_list.append(cmd)

    # interface.api.json: sw_interface_flexiwan_label_add_del (..., sw_if_index, n_labels, labels, ...)
    if not is_wifi and 'multilink' in params and 'labels' in params['multilink']:
        labels = params['multilink']['labels']
        if len(labels) > 0:
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "python"
            cmd['cmd']['descr']   = "add multilink labels into interface %s %s: %s" % (iface_addr, dev_id, labels)
            cmd['cmd']['params']  = {
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels':   labels,
                                        'next_hop': gw,
                                        'dev_id':   dev_id,
                                        'remove':   False
                                      }
            }
            # Cache 'next_hop' resolved by vpp_multilink_update_labels on 'add-interface',
            # to be used on 'remove-interface'. This is needed for DHCP interfaces,
            # where GW can be changed/removed under our legs
            #
            cache_key = 'next_hop-%s' % dev_id
            cmd['cmd']['cache_ret_val'] = ('next_hop', cache_key)

            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['descr']  = "remove multilink labels from interface %s %s: %s" % (iface_addr, dev_id, labels)
            cmd['revert']['params'] = {
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels':   labels,
                                        'dev_id':   dev_id,
                                        'remove':   True
                                      },
                            'substs': [ { 'add_param':'next_hop', 'val_by_key':cache_key} ],
            }
            cmd_list.append(cmd)

    # Setup NAT config on WAN interface
    if 'type' not in params or params['type'].lower() == 'wan':
        cmd_list.extend(fw_nat_command_helpers.get_nat_wan_setup_config(dev_id))

    # Update ospfd configuration.
    if 'routing' in params and params['routing'].lower() == 'ospf':
        ospf = params.get('ospf', {})
        area = ospf.get('area', '0.0.0.0')
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['descr']   =  "add network %s to OSPF" % iface_addr
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "network %s area %s" % (iface_addr, area)]
                }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'commands': ["router ospf", "no network %s area %s" % (iface_addr, area)]
                }
        }
        cmd['revert']['descr']   =  "remove network %s from OSPF" % iface_addr
        cmd_list.append(cmd)

        # OSPF per interface configuration
        frr_cmd = []
        restart_frr = False
        helloInterval = ospf.get('helloInterval')
        if helloInterval:
            frr_cmd.append('ip ospf hello-interval %s' % helloInterval)

        deadInterval = ospf.get('deadInterval')
        if deadInterval:
            frr_cmd.append('ip ospf dead-interval %s' % deadInterval)

        cost = ospf.get('cost')
        if cost:
            frr_cmd.append('ip ospf cost %s' % cost)

        keyId = ospf.get('keyId')
        key = ospf.get('key')
        if keyId and key:
            restart_frr = True
            frr_cmd.append('ip ospf message-digest-key %s md5 %s' % (keyId, key))
            frr_cmd.append('ip ospf authentication message-digest')

        if frr_cmd:
            frr_cmd_revert = list(map(lambda x: 'no %s' % x, frr_cmd))

            # if interface is inside a bridge, we need to put the ospf on the bvi loop interface
            func = 'dev_id_to_tap'
            arg = dev_id
            if bridge_addr:
                func = 'bridge_addr_to_bvi_interface_tap'
                arg = bridge_addr

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']   = "python"
            cmd['cmd']['params'] = {
                    'module': 'fwutils',
                    'func': 'frr_vtysh_run',
                    'args': {
                        'commands'   : ["interface DEV-STUB"] + frr_cmd,
                        'restart_frr': restart_frr
                    },
                    'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func': func, 'arg': arg} ]
            }
            cmd['cmd']['descr']   =  "add OSPF per link configuration of interface %s" % iface_addr
            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func': 'frr_vtysh_run',
                    'args': {
                        'commands'   : ["interface DEV-STUB"] + frr_cmd_revert,
                        'restart_frr': restart_frr
                    },
                    'substs': [ {'replace':'DEV-STUB', 'key': 'commands', 'val_by_func': func, 'arg': arg} ]
            }
            cmd['revert']['descr']   =  "remove OSPF per link configuration of interface %s" % iface_addr
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
                            'mac'     : 'ff:ff:ff:ff:ff:ff',
                    },
                    'substs': [ { 'add_param':'gw', 'val_by_func':'lte_get_ip_configuration', 'arg':[dev_id, 'gateway'] }]
        }
        cmd['cmd']['descr']         = "create static arp entry for dev_id %s" % dev_id
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "exec"
        cmd['cmd']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_ip_configuration', 'arg': [dev_id, 'gateway'] } ]},
                                "sudo arp -s DEV-STUB 00:00:00:00:00:00" ]
        cmd['cmd']['descr'] = "set arp entry on linux for lte interface"
        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['descr']  = "remove arp entry on linux for lte interface"
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_ip_configuration', 'arg': [dev_id, 'gateway'] } ]},
                                    "sudo arp -d DEV-STUB || true" ]
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
            pipe action mirred egress mirror dev %s \
            pipe action drop" % iface_name,
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
            "tc filter add dev %s parent ffff: \
            protocol all prio 2 u32 \
            match u32 0 0 flowid 1:1 \
            action pedit ex munge eth dst set VPP-MAC \
            pipe action mirred egress mirror dev DEV-STUB \
            pipe action drop" % iface_name,
            { 'substs': [
                {'replace':'VPP-MAC', 'val_by_func':'get_vpp_tap_interface_mac_addr', 'arg':dev_id },
                {'replace':'DEV-STUB', 'val_by_func':'linux_tap_by_interface_name', 'arg':iface_name }
            ] }
        ]
        cmd['cmd']['descr'] = "add filter traffic control command for tap and wwan interfaces"
        cmd_list.append(cmd)


    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "postprocess add-interface"
    cmd['cmd']['params']  = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_add_interface_after',
                    'args'  : { 'type': str(int_type).lower() },
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "preprocess remove-interface"
    cmd['revert']['params'] = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_remove_interface_before',
                    'args'  : { 'type': str(int_type).lower() },
                    'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ]
    }
    cmd_list.append(cmd)

    return cmd_list

def modify_interface(new_params, old_params):
    """Generate commands to modify interface configuration in Linux and VPP

    :param new_params:  The new configuration received from flexiManage.
    :param old_params:  The current configuration of interface.

    :returns: List of commands.
    """
    cmd_list = []

    # For now we don't support real translation to command list.
    # We just return empty list if new parameters have no impact on Linux or
    # VPP, like PublicPort, and non-empty dummy list if parameters do have impact
    # and translation is needed. In last case the modification will be performed
    # by replacing modify-interface with pair of remove-interface & add-interface.
    # I am an optimistic person, so I believe that hack will be removed at some
    # point and real translation will be implemented.

    # Remove all not impacting parameters from both new and old parameters and
    # compare them. If they are same, no translation is needed.
    #
    not_impacting_params = [ 'PublicIP', 'PublicPort', 'useStun']
    copy_old_params = copy.deepcopy(old_params)
    copy_new_params = copy.deepcopy(new_params)

    for param in not_impacting_params:
        if param in copy_old_params:
            del copy_old_params[param]
        if param in copy_new_params:
            del copy_new_params[param]

    same = fwutils.compare_request_params(copy_new_params, copy_old_params)
    if not same:    # There are different impacting parameters
        cmd_list = [ 'stub' ]
    return cmd_list

def get_request_key(params):
    """Get add interface command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-interface:%s' % params['dev_id']
