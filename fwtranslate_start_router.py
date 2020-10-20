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

import fwnetplan
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
#        "hw_addr": [
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

    # Initialize some stuff before router start
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "fwrouter_api._on_start_router_before()"
    cmd['cmd']['params']  = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_start_router_before'
    }
    cmd_list.append(cmd)

    # Remove interfaces from Linux.
    #   sudo ip link set dev enp0s8 down
    #   sudo ip addr flush dev enp0s8
    # The interfaces to be removed are stored within 'add-interface' requests
    # in the configuration database.
    hw_addr_list         = []
    hw_addr_list_vmxnet3 = []
    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for params in interfaces:        
        linux_if  = fwutils.hw_addr_to_linux_if(params['hw_addr'])
        if linux_if:
            # Firstly mark 'vmxnet3' interfaces as they need special care:
            #   1. They should not appear in /etc/vpp/startup.conf.
            #      If they appear in /etc/vpp/startup.conf, vpp will capture
            #      them with vfio-pci driver, and 'create interface vmxnet3'
            #      command will fail with 'device in use'.
            #   2. They require additional VPP call vmxnet3_create on start
            #      and complement vmxnet3_delete on stop
            if fwutils.hw_addr_is_vmxnet3(params['hw_addr']):
                hw_addr_list_vmxnet3.append(params['hw_addr'])
            else:
                hw_addr_list.append(params['hw_addr'])

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "exec"
            cmd['cmd']['params']  = [ "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (linux_if ,linux_if ) ]
            cmd['cmd']['descr']   = "shutdown dev %s in Linux" % linux_if
            cmd_list.append(cmd)

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    netplan_files = fwnetplan.get_netplan_filenames()
    fwnetplan._set_netplan_filename(netplan_files)

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    if len(hw_addr_list) > 0:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_add_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': hw_addr_list }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
        cmd['revert']['params'] = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_remove_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': hw_addr_list }
        }
        cmd_list.append(cmd)

    # Enable NAT in vpp configuration file
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
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "stop vpp"
    cmd['revert']['params'] = { 'module': 'fwutils', 'func': 'stop_vpp' }
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "connect to vpp papi"
    cmd['cmd']['params']    = { 'object': 'fwglobals.g.router_api.vpp_api', 'func': 'connect_to_vpp' }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "disconnect from vpp papi"
    cmd['revert']['params'] = { 'object': 'fwglobals.g.router_api.vpp_api', 'func': 'disconnect_from_vpp' }
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
    cmd['cmd']['descr'] = "punt ip broadcast"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "backup Linux netplan files"
    cmd['cmd']['params']  = {
        'module': 'fwnetplan',
        'func'  : 'backup_linux_netplan_files'
    }
    cmd['revert'] = {}
    cmd['revert']['name'] = "python"
    cmd['revert']['descr'] = "restore linux netplan files"
    cmd['revert']['params']  = {
        'module': 'fwnetplan',
        'func'  : 'restore_linux_netplan_files'
    }
    cmd_list.append(cmd)

    # vmxnet3 interfaces are not created by VPP on bootup, so create it explicitly
    # vmxnet3.api.json: vmxnet3_create (..., pci_addr, enable_elog, rxq_size, txq_size, ...)
    # Note we do it here and not on 'add-interface' as 'modify-interface' is translated
    # into 'remove-interface' and 'add-interface', so we want to avoid deletion
    # and creation interface on every 'modify-interface'. There is no sense to do
    # that and it causes problems in FIB, when default route interface is deleted.
    for hw_addr in hw_addr_list_vmxnet3:
        addr_type, _ = fwutils.hw_if_addr_to_type_and_addr(hw_addr)
        if (addr_type === "pci"):
            pci_bytes = fwutils.pci_str_to_bytes(hw_addr)
            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "vmxnet3_create"
            cmd['cmd']['descr']   = "create vmxnet3 interface for %s" % hw_addr
            cmd['cmd']['params']  = { 'pci_addr':pci_bytes }
            cmd['revert'] = {}
            cmd['revert']['name']   = "vmxnet3_delete"
            cmd['revert']['descr']  = "delete vmxnet3 interface for %s" % hw_addr
            cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'hw_addr_to_vpp_sw_if_index', 'arg':hw_addr } ] }
            cmd_list.append(cmd)

    # Once VPP started, apply configuration to it.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "FWROUTER_API::_on_apply_router_config()"
    cmd['cmd']['params']  = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_apply_router_config'
    }
    cmd_list.append(cmd)

    # Finalize some stuff after VPP start / before VPP stops.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "fwrouter_api._on_start_router_after()"
    cmd['cmd']['params']  = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_start_router_after'
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_before()"
    cmd['revert']['params'] = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_stop_router_before'
    }
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(*params):
    """Get start router command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'start-router'

