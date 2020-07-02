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

import os
import re

import fwglobals
import fwutils

# start_router
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "pci": [
#           "0000:00:08.00",
#           "0000:00:09.00"
#        ]
#      }
#    }
#|
# into list of commands:
#
#    1. generates ospfd.conf for FRR
#    01. print CONTENT > ospfd.conf
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#
#    2.Linux_sh1.sh
#    ------------------------------------------------------------
#    02. sudo ip link set dev enp0s8 down &&
#        sudo ip addr flush dev enp0s8
#    03. sudo ip link set dev enp0s9 down &&
#        sudo ip addr flush dev enp0s9
#
#    3.vpp.cfg
#    ------------------------------------------------------------
#    04. sudo systemtctl start vpp
#    05. sudo vppctl enable tap-inject
#
#
def start_router(params=None):
    """Generate commands to start VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    # Remove interfaces from Linux.
    #   sudo ip link set dev enp0s8 down
    #   sudo ip addr flush dev enp0s8
    # The interfaces to be removed are stored within 'add-interface' requests
    # in the configuration database.
    pci_list         = []
    pci_list_vmxnet3 = []
    for key in fwglobals.g.router_api.db_requests.db:
        if re.match('add-interface', key):
            (_, params) = fwglobals.g.router_api.db_requests.fetch_request(key)
            iface_pci  = fwutils.pci_to_linux_iface(params['pci'])
            if iface_pci:
                # Firstly mark 'vmxnet3' interfaces as they need special care:
                #   1. They should not appear in /etc/vpp/startup.conf.
                #      If they appear in /etc/vpp/startup.conf, vpp will capture
                #      them with vfio-pci driver, and 'create interface vmxnet3'
                #      command will fail with 'device in use'.
                #   2. They require additional VPP call vmxnet3_create on start
                #      and complement vmxnet3_delete on stop
                if fwutils.pci_is_vmxnet3(params['pci']):
                    pci_list_vmxnet3.append(params['pci'])
                else:
                    pci_list.append(params['pci'])

                cmd = {}
                cmd['cmd'] = {}
                cmd['cmd']['name']    = "exec"
                cmd['cmd']['params']  = [ "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (iface_pci ,iface_pci ) ]
                cmd['cmd']['descr']   = "shutdown dev %s in Linux" % iface_pci
                cmd['revert'] = {}
                cmd['revert']['name']    = "exec"
                cmd['revert']['params']  = [ "sudo netplan apply" ]
                cmd['revert']['descr']  = "apply netplan configuration"
                cmd_list.append(cmd)

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    if len(pci_list) > 0:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_add_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': pci_list }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
        cmd['revert']['params'] = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_remove_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': pci_list }
        }
        cmd_list.append(cmd)

    # # Enable NAT in vpp configuration file
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add NAT to %s" % vpp_filename
    cmd['cmd']['params']  = {
        'module': 'fwutils',
        'func'  : 'vpp_startup_conf_add_nat',
        'args'  : { 'vpp_config_filename' : vpp_filename }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove NAT from %s" % vpp_filename
    cmd['revert']['params'] = {
        'module': 'fwutils',
        'func'  : 'vpp_startup_conf_remove_nat',
        'args'  : { 'vpp_config_filename' : vpp_filename }
    }
    cmd_list.append(cmd)

    #  Create commands that start vpp and configure it with addresses
    #  sudo systemtctl start vpp
    #  <connect to python bindings of vpp and than run the rest>
    #  sudo vppctl enable tap-inject
    cmd = {}
    cmd['cmd'] = {}                     # vfio-pci related stuff is needed for vmxnet3 interfaces
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'sudo modprobe vfio-pci  &&  (echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)' ]
    cmd['cmd']['descr']   = "enable vfio-pci driver in Linux"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'sudo systemctl start vpp; if [ -z "$(pgrep vpp)" ]; then exit 1; fi' ]
    cmd['cmd']['descr']   = "start vpp"
    cmd['revert'] = {}
    cmd['revert']['name']   = "stop_router"
    cmd['revert']['descr']  = "stop router"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "connect_to_router"
    cmd['cmd']['descr']   = "connect to vpp papi"
    cmd['revert'] = {}
    cmd['revert']['name']   = "disconnect_from_router"
    cmd['revert']['descr']  = "disconnect from vpp papi"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ "sudo vppctl enable tap-inject" ]
    cmd['cmd']['descr']   = "enable tap-inject"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "nat44_forwarding_enable_disable"
    cmd['cmd']['descr']   = "enable NAT forwarding"
    cmd['cmd']['params']  = { 'enable':1 }
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "exec"
    cmd['cmd']['params'] = ["sudo vppctl ip route add 255.255.255.255/32 via punt"]
    cmd['cmd']['descr'] = "punt ip brodcast"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "create %s" % fwglobals.g.NETPLAN_FILE
    cmd['cmd']['params']  = {
        'module': 'fwutils',
        'func'  : 'add_del_netplan_file',
        'args'  : {'is_add': 1}
    }
    cmd['revert'] = {}
    cmd['revert']['name'] = "python"
    cmd['revert']['descr'] = "remove %s" % fwglobals.g.NETPLAN_FILE
    cmd['revert']['params']  = {
        'module': 'fwutils',
        'func'  : 'add_del_netplan_file',
        'args'  : {'is_add': 0}
    }
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = 'exec'
    cmd['cmd']['params']  = [ 'sudo ip route flush 0/0;sudo netplan apply;sleep 10' ]
    cmd['cmd']['descr']   = "netplan apply"
    cmd_list.append(cmd)
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "Convert routes in multipath"
    cmd['cmd']['params']  = {
        'module': 'fwutils',
        'func'  : '_convert_all_routes',
        'args'  : {}
    }
    cmd_list.append(cmd)
    # vmxnet3 interfaces are not created by VPP on bootup, so create it explicitly
    # vmxnet3.api.json: vmxnet3_create (..., pci_addr, enable_elog, rxq_size, txq_size, ...)
    # Note we do it here and not on 'add-interface' as 'modify-interface' is translated
    # into 'remove-interface' and 'add-interface', so we want to avoid deletion
    # and creation interface on every 'modify-interface'. There is no sense to do
    # that and it causes problems in FIB, when default route interface is deleted.
    for pci in pci_list_vmxnet3:
        pci_bytes = fwutils.pci_str_to_bytes(pci)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "vmxnet3_create"
        cmd['cmd']['descr']   = "create vmxnet3 interface for %s" % pci
        cmd['cmd']['params']  = { 'pci_addr':pci_bytes }
        cmd['revert'] = {}
        cmd['revert']['name']   = "vmxnet3_delete"
        cmd['revert']['descr']  = "delete vmxnet3 interface for %s" % pci
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'pci_to_vpp_sw_if_index', 'arg':pci } ] }
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(*params):
    """Get start router command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'start-router'

