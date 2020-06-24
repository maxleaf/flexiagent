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
import fwtranslate_revert
import fwutils

# add_interface
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-interface",
#      "params": {
#           "pci":"0000:00:08.00",
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
def _change_netplan_conf(pci, dhcp, ip, gw, cmd_list):
    """Generate commands to change Netplan config file.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    args = {'is_add': 1, 'pci': pci, 'dhcp': dhcp, 'ip': ip, 'gw': gw}
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['params'] = {
        'module': 'fwutils',
        'func': 'add_remove_netplan_interface',
        'args': args
    }
    cmd['cmd']['descr'] = "modify netplan config file"
    cmd['revert'] = {}
    cmd['revert']['name'] = 'python'
    cmd['revert']['params'] = {
        'module': 'fwutils',
        'func': 'add_remove_netplan_interface',
        'args': copy.deepcopy(args)
    }
    cmd['revert']['params']['args']['is_add'] = 0
    cmd['revert']['descr'] = "clean netplan config file"

    cmd_list.append(cmd)


def _set_dhcp_detect(pci, cmd_list):
    """Generate commands to set DHCP detect ib VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    add_params = {
        'module': 'fwutils',
        'func': 'vpp_set_dhcp_detect',
        'args': {'pci': pci, 'remove': False}
    }

    del_params = copy.deepcopy(add_params)
    del_params['args']['remove'] = True

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "Enable DHCP detect"
    cmd['cmd']['params']    = add_params
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "Disable DHCP detect"
    cmd['revert']['params'] = del_params
    cmd_list.append(cmd)

    return cmd_list

def add_interface(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    iface_pci  = params['pci']
    iface_addr = params.get('addr', '')
    iface_addr_bytes = ''
    if iface_addr:
        iface_addr_bytes, _ = fwutils.ip_str_to_bytes(iface_addr)

    ######################################################################
    #  NO NEED TO SET IP AND UP/DOWN STATE IN VPP !
    #  WE DO THAT IN LINUX, TAP-INJECT REFLECTS THESE CHANGES TO VPP
    #  (as well we avoid various errors like 'duplicated address' on add
    #   or 'illegal addess' on delete ;))
    #  Note, as on Nov-2019 the opposite direction doesn't work,
    #  delete address in VPP doesn't delete it in Linux ?)
    ######################################################################

    # Add interface section into Netplan configuration file
    gw = params.get('gateway', None)
    _change_netplan_conf(iface_pci, params['dhcp'], iface_addr, gw, cmd_list)
    if params['dhcp'].lower() == 'yes':
        _set_dhcp_detect(iface_pci, cmd_list)

    # interface.api.json: sw_interface_flexiwan_label_add_del (..., sw_if_index, n_labels, labels, ...)
    if 'multilink' in params and 'labels' in params['multilink']:
        labels = params['multilink']['labels']
        if len(labels) > 0:
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "python"
            cmd['cmd']['descr']   = "add multilink labels into interface %s %s: %s" % (iface_addr, iface_pci, labels)
            cmd['cmd']['params']  = {
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels':   labels,
                                        'next_hop': params.get('gateway'),
                                        'dev':      iface_pci,
                                        'remove':   False
                                      }
            }
            cmd['revert'] = {}
            cmd['revert']['name']   = "python"
            cmd['revert']['descr']  = "remove multilink labels from interface %s %s: %s" % (iface_addr, iface_pci, labels)
            cmd['revert']['params'] = {
                            'module': 'fwutils',
                            'func'  : 'vpp_multilink_update_labels',
                            'args'  : { 'labels':   labels,
                                        'next_hop': params.get('gateway'),
                                        'dev':      iface_pci,
                                        'remove':   True
                                      }
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
        cmd['cmd']['name']    = "nat44_add_del_interface_addr"
        cmd['cmd']['descr']   = "enable NAT for interface %s (%s)" % (iface_pci, iface_addr)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':1, 'twice_nat':0 }
        cmd['revert'] = {}
        cmd['revert']['name']   = "nat44_add_del_interface_addr"
        cmd['revert']['descr']  = "disable NAT for interface %s (%s)" % (iface_pci, iface_addr)
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':0, 'twice_nat':0 }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "nat44_interface_add_del_output_feature"
        cmd['cmd']['descr']   = "add interface %s (%s) to output path" % (iface_pci, iface_addr)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':1, 'is_inside':0 }
        cmd['revert'] = {}
        cmd['revert']['name']   = "nat44_interface_add_del_output_feature"
        cmd['revert']['descr']  = "remove interface %s (%s) from output path" % (iface_pci, iface_addr)
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':0, 'is_inside':0 }
        cmd_list.append(cmd)

        # nat.api.json: nat44_add_del_identity_mapping (..., is_add, ...)
        vxlan_port = 4789
        udp_proto = 17

        if iface_addr_bytes:
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']          = "nat44_add_del_identity_mapping"
            cmd['cmd']['params']        = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                            'ip_address':iface_addr_bytes, 'port':vxlan_port, 'protocol':udp_proto, 'is_add':1, 'addr_only':0 }
            cmd['cmd']['descr']         = "create nat identity mapping %s -> %s" % (params['addr'], vxlan_port)
            cmd['revert'] = {}
            cmd['revert']['name']       = 'nat44_add_del_identity_mapping'
            cmd['revert']['params']     = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                            'ip_address':iface_addr_bytes, 'port':vxlan_port, 'protocol':udp_proto, 'is_add':0, 'addr_only':0 }
            cmd['revert']['descr']      = "delete nat identity mapping %s -> %s" % (params['addr'], vxlan_port)

            cmd_list.append(cmd)

    # On LAN interfaces run
    #   'set interface nat44 in GigabitEthernet0/8/0 output-feature'
    # nat.api.json: nat44_interface_add_del_output_feature(inside=1)
    else:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "nat44_interface_add_del_output_feature"
        cmd['cmd']['descr']   = "add interface %s (%s) to output path" % (iface_pci, iface_addr)
        cmd['cmd']['params']  = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':1, 'is_inside':1 }
        cmd['revert'] = {}
        cmd['revert']['name']   = "nat44_interface_add_del_output_feature"
        cmd['revert']['descr']  = "remove interface %s (%s) from output path" % (iface_pci, iface_addr)
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':iface_pci } ],
                                    'is_add':0, 'is_inside':1 }
        cmd_list.append(cmd)

    # Update ospfd.conf.
    ospfd_file = fwglobals.g.FRR_OSPFD_FILE
    if 'routing' in params and params['routing'].lower() == 'ospf':

        router_id = iface_addr.split('/')[0]    # Get rid of address length
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "exec"
        cmd['cmd']['descr']   = "initialize %s with router id %s" % (ospfd_file, router_id)
        cmd['cmd']['params']  = [
            'sudo printf "' + \
            'hostname ospfd\n' + \
            'password zebra\n' + \
            'log file /var/log/frr/ospfd.log informational\n' + \
            'log stdout\n' + \
            '!\n' + \
            'router ospf\n' + \
            '    ospf router-id ' + router_id + '\n' + \
            '!\n' + \
            '" > ' + ospfd_file ]
        cmd['precondition'] = {}
        cmd['precondition']['usage']   = "precondition"
        cmd['precondition']['name']    = "exec"
        cmd['precondition']['descr']   = "%s doesn't exists" % ospfd_file
        cmd['precondition']['params']  = [ "! test -f %s" % ospfd_file ]
        # Don't delete /etc/frr/ospfd.conf on revert, as it might be used by other interfaces too
        cmd_list.append(cmd)

        # Ensure that ospfd is switched on in /etc/frr/daemons.
        frr_filename = fwglobals.g.FRR_CONFIG_FILE
        ospfd_status = os.popen('grep ospfd=no %s' % frr_filename).read()
        if re.match('ospfd=no', ospfd_status):
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "exec"
            cmd['cmd']['params']  = [ 'sudo sed -i -E "s/ospfd=no/ospfd=yes/" %s' % frr_filename ]
            cmd['cmd']['descr']   = "enable ospf daemon"
            # There is no revert on purpose: we leave it always ON to simplify code.
            # If there is no OSPF interfaces, frr will not send OSPF messages.
            # Implement revert on demand :)
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

    return cmd_list

def get_request_key(params):
    """Get add interface command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-interface:%s' % params['pci']
