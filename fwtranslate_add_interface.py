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
def add_interface(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']

    iface_addr = params.get('addr', '')
    iface_addr_bytes = ''
    if iface_addr:
        iface_addr_bytes, _ = fwutils.ip_str_to_bytes(iface_addr)

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

    is_wifi = fwutils.is_wifi_interface_by_dev_id(dev_id)
    is_lte = fwutils.is_lte_interface_by_dev_id(dev_id) if not is_wifi else False
    is_non_dpdk = is_wifi or is_lte

    if is_non_dpdk:
        dhcp = 'no'

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
                    'func': 'start_hostapd',
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
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']      = "exec"
            cmd['cmd']['descr']     = "UP interface %s in Linux" % iface_name
            cmd['cmd']['params']    = [ "sudo ip link set dev %s up" %  iface_name]
            cmd['revert'] = {}
            cmd['revert']['name']   = "exec"
            cmd['revert']['descr']  = "Down interface %s in Linux" % iface_name
            cmd['revert']['params'] = [ "sudo ip link set dev %s down" %  iface_name]
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
                    'type'     : int_type
        }
    }

    if is_lte:
        netplan_params['substs'] = [
            { 'add_param':'ip', 'val_by_func':'lte_get_provider_config', 'arg': [dev_id, 'IP'] },
            { 'add_param':'gw', 'val_by_func':'lte_get_provider_config', 'arg': [dev_id, 'GATEWAY'] }
        ]

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

    # Enable NAT.
    # On WAN interfaces run
    #   'nat44 add interface address GigabitEthernet0/9/0'
    #   'set interface nat44 out GigabitEthernet0/9/0 output-feature'
    # nat.api.json: nat44_add_del_interface_addr() & nat44_interface_add_del_output_feature(inside=0)
    if 'type' not in params or params['type'].lower() == 'wan':
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']      = "python"
        cmd['cmd']['descr']     = "enable NAT for interface address %s" % dev_id
        cmd['cmd']['params']    = {
                                    'module': 'fwutils',
                                    'func':   'vpp_nat_addr_update_on_interface_add',
                                    'args':   {
                                        'dev_id': dev_id,
                                        'metric': metric,
                                        'remove': False
                                    }
                                  }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "disable NAT for interface %s" % dev_id
        cmd['revert']['params'] = {
                                    'module': 'fwutils',
                                    'func':   'vpp_nat_addr_update_on_interface_add',
                                    'args':   {
                                        'dev_id': dev_id,
                                        'metric': metric,
                                        'remove': True
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

        # nat.api.json: nat44_add_del_identity_mapping (..., is_add, ...)
        vxlan_port = 4789
        udp_proto = 17

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']          = "nat44_add_del_identity_mapping"
        cmd['cmd']['params']        = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                        'port':vxlan_port, 'protocol':udp_proto, 'is_add':1 }
        cmd['cmd']['descr']         = "create nat identity mapping %s -> %s" % (dev_id, vxlan_port)
        cmd['revert'] = {}
        cmd['revert']['name']       = 'nat44_add_del_identity_mapping'
        cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ],
                                        'port':vxlan_port, 'protocol':udp_proto, 'is_add':0 }
        cmd['revert']['descr']      = "delete nat identity mapping %s -> %s" % (dev_id, vxlan_port)

        cmd_list.append(cmd)

    # Update ospfd.conf.
    ospfd_file = fwglobals.g.FRR_OSPFD_FILE
    if 'routing' in params and params['routing'].lower() == 'ospf':

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
                                        'router_id':        iface_addr.split('/')[0]   # Get rid of address length
                                    }
                                }
        # Don't delete /etc/frr/ospfd.conf on revert, as it might be used by other interfaces too
        cmd_list.append(cmd)

        # Escape slash in address with length to prevent sed confusing
        addr = iface_addr.split('/')[0] + r"\/" + iface_addr.split('/')[1]
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   =  "add %s to %s" % (iface_addr , ospfd_file)
        cmd['cmd']['params']  = [
            'if [ -z "$(grep \'network %s\' %s)" ]; then sed -i -E "s/([ ]+)(ospf router-id .*)/\\1\\2\\n\\1network %s area 0.0.0.0/" %s; fi' %
            (addr , ospfd_file , addr , ospfd_file) ]
        cmd['revert'] = {}
        cmd['revert']['name']    = "exec"
        cmd['revert']['descr']   =  "remove %s from %s" % (iface_addr , ospfd_file)
        # Delete 'network' parameter from ospfd.conf.
        # If no more networks are configured, delete file itself. This is to clean the 'ospf router-id' field.
        # Note more sophisticated code is needed to replace 'ospf router-id' value with other network
        # that might exist in ospfd.conf after removal of this interface. Implement it on demand :)
        cmd['revert']['params']  = [
            'sed -i -E "/[ ]+network %s area 0.0.0.0.*/d" %s; if [ -z "$(grep \' network \' %s)" ]; then rm -rf %s; fi; sudo systemctl restart frr' %
            (addr , ospfd_file , ospfd_file , ospfd_file) ]
        cmd['revert']['filter']  = 'must'   # When 'remove-XXX' commands are generated out of the 'add-XXX' commands, run this command even if vpp doesn't run
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = 'exec'
        cmd['cmd']['params']  = [ 'sudo systemctl restart frr; if [ -z "$(pgrep frr)" ]; then exit 1; fi' ]
        cmd['cmd']['descr']   = "restart frr"
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
                    'substs': [ { 'add_param':'gw', 'val_by_func':'lte_get_provider_config', 'arg':[dev_id, 'GATEWAY'] }]
        }
        cmd['cmd']['descr']         = "create static arp entry for dev_id %s" % dev_id
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "exec"
        cmd['cmd']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_provider_config', 'arg': [dev_id, 'GATEWAY'] } ]},
                                "sudo arp -s DEV-STUB 00:00:00:00:00:00" ]
        cmd['cmd']['descr'] = "set arp entry on linux for lte interface"
        cmd['revert'] = {}
        cmd['revert']['name']   = "exec"
        cmd['revert']['descr']  = "remove arp entry on linux for lte interface"
        cmd['revert']['params'] = [ {'substs': [ {'replace':'DEV-STUB', 'val_by_func':'lte_get_provider_config', 'arg': [dev_id, 'GATEWAY'] } ]},
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
