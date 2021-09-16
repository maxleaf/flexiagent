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

import os
import re

import fwnetplan
import fwglobals
import fwikev2
import fwutils
import fw_nat_command_helpers

# start_router
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "dev_id": [
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
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "fwrouter_api._on_stop_router_after()"
    cmd['revert']['params'] = {
                    'object': 'fwglobals.g.router_api',
                    'func'  : '_on_stop_router_after'
    }
    cmd_list.append(cmd)

    dev_id_list         = []
    pci_list_vmxnet3 = []
    assigned_linux_interfaces = []

    # Remove interfaces from Linux.
    #   sudo ip link set dev enp0s8 down
    #   sudo ip addr flush dev enp0s8
    # The interfaces to be removed are stored within 'add-interface' requests
    # in the configuration database.
    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for params in interfaces:
        linux_if  = fwutils.dev_id_to_linux_if(params['dev_id'])
        if linux_if:

            cmd = {}
            cmd['cmd'] = {}
            cmd['cmd']['name']    = "exec"
            cmd['cmd']['params']  = [ "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (linux_if ,linux_if ) ]
            cmd['cmd']['descr']   = "shutdown dev %s in Linux" % linux_if
            cmd_list.append(cmd)

            # Non-dpdk interface should not appear in /etc/vpp/startup.conf because they don't have a pci address.
            # Additional spacial logic for these interfaces is at add_interface translator
            if fwutils.is_non_dpdk_interface(params['dev_id']):
                continue
            assigned_linux_interfaces.append(linux_if)

            # Mark 'vmxnet3' interfaces as they need special care:
            #   1. They should not appear in /etc/vpp/startup.conf.
            #      If they appear in /etc/vpp/startup.conf, vpp will capture
            #      them with vfio-pci driver, and 'create interface vmxnet3'
            #      command will fail with 'device in use'.
            #   2. They require additional VPP call vmxnet3_create on start
            #      and complement vmxnet3_delete on stop
            if fwutils.dev_id_is_vmxnet3(params['dev_id']):
                pci_list_vmxnet3.append(params['dev_id'])
            else:
                dev_id_list.append(params['dev_id'])

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "enable coredump to %s" % vpp_filename
    cmd['cmd']['params']  = {
        'module': 'fw_vpp_coredump_utils',
        'func'  : 'vpp_coredump_setup_startup_conf',
        'args'  : { 'vpp_config_filename' : vpp_filename, 'enable': 1 }
    }
    cmd_list.append(cmd)

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    if len(dev_id_list) > 0:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_add_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': dev_id_list }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
        cmd['revert']['params'] = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_remove_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': dev_id_list }
        }
        cmd_list.append(cmd)
    elif len(pci_list_vmxnet3) == 0:
        # When the list of devices in the startup.conf file is empty, the vpp attempts
        # to manage all the down linux interfaces.
        # Since we allow non-dpdk interfaces (LTE, WiFi), this list could be empty.
        # In order to prevent vpp from doing so, we need to add the "no-pci" flag.
        # Note, on VMWare don't use no-pci, so vpp will capture interfaces and
        # vmxnet3_create() called after vpp start will succeed.
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "add no-pci flag to %s" % vpp_filename
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_add_nopci',
            'args'  : { 'vpp_config_filename' : vpp_filename }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "remove no-pci flag to %s" % vpp_filename
        cmd['revert']['params'] = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_remove_nopci',
            'args'  : { 'vpp_config_filename' : vpp_filename }
        }
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

    if assigned_linux_interfaces:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "Unload to-be-VPP interfaces from linux networkd"
        cmd['cmd']['params']  = {
            'module': 'fwnetplan',
            'func'  : 'netplan_unload_vpp_assigned_ports',
            'args'  : { 'assigned_linux_interfaces' : assigned_linux_interfaces }
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
    cmd['cmd']['name']    = "python"
    cmd['cmd']['params']  = {'module': 'fwutils', 'func' : 'vpp_enable_tap_inject'}
    cmd['cmd']['descr']   = "enable tap-inject"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "nat44_plugin_enable_disable"
    cmd['cmd']['descr']   = "enable NAT pluging and configure it"
    cmd['cmd']['params']  = { 'enable':1, 'flags': 1,  # nat.h: _(0x01, IS_ENDPOINT_DEPENDENT)
                              'sessions':  100000 }    # Defaults: users=1024, sessions=10x1024, in multicore these parameters are per worker thread
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
    cmd['cmd']['descr'] = "backup DHCP server files"
    cmd['cmd']['params']  = {
        'module': 'fwutils',
        'func'  : 'backup_dhcpd_files'
    }
    cmd['revert'] = {}
    cmd['revert']['name'] = "python"
    cmd['revert']['descr'] = "restore DHCP server files"
    cmd['revert']['params']  = {
        'module': 'fwutils',
        'func'  : 'restore_dhcpd_files'
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'sudo systemctl start frr; if [ -z "$(pgrep frr)" ]; then exit 1; fi' ]
    cmd['cmd']['descr']   = "start frr"
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['descr']  = "stop frr"
    cmd['revert']['params'] = [ 'sudo systemctl stop frr' ]
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "Setup FRR configuration"
    cmd['cmd']['params']  = {'module': 'fwutils', 'func' : 'frr_setup_config'}
    cmd_list.append(cmd)

    # We set up the redistribution filter now. We don't want to set it on every add_route translation.
    # At this time, the filter list will be empty, so no kernel route will be redistributed.
    # When we need to redistribute a static route, we'll add it to the filter list.
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['params'] = {
            'module': 'fwutils',
            'func':   'frr_create_redistribution_filter',
            'args': {
                'router': 'router ospf',
                'acl': fwglobals.g.FRR_OSPF_ACL,
                'route_map': fwglobals.g.FRR_OSPF_ROUTE_MAP,
                'route_map_num': '1', # 1 is for OSPF
            }
    }
    cmd['cmd']['descr']   =  "add ospf redistribution filter"
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
            'module': 'fwutils',
            'func':   'frr_create_redistribution_filter',
            'args': {
                'router': 'router ospf',
                'acl': fwglobals.g.FRR_OSPF_ACL,
                'route_map': fwglobals.g.FRR_OSPF_ROUTE_MAP,
                'route_map_num': '1', # 1 is for OSPF
                'revert': True
            }
    }
    cmd['revert']['descr']   =  "remove ospf redistribution filter"
    cmd_list.append(cmd)

    # Setup Global VPP NAT parameters
    # Post VPP NAT/Firewall changes - The param need to be false
    cmd_list.append(fw_nat_command_helpers.get_nat_forwarding_config(False))

    # vmxnet3 interfaces are not created by VPP on bootup, so create it explicitly
    # vmxnet3.api.json: vmxnet3_create (..., pci_addr, enable_elog, rxq_size, txq_size, ...)
    # Note we do it here and not on 'add-interface' as 'modify-interface' is translated
    # into 'remove-interface' and 'add-interface', so we want to avoid deletion
    # and creation interface on every 'modify-interface'. There is no sense to do
    # that and it causes problems in FIB, when default route interface is deleted.
    for dev_id in pci_list_vmxnet3:
        _, pci = fwutils.dev_id_parse(dev_id)
        pci_bytes = fwutils.pci_str_to_bytes(pci)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "vmxnet3_create"
        cmd['cmd']['descr']   = "create vmxnet3 interface for %s" % pci
        cmd['cmd']['params']  = { 'pci_addr':pci_bytes }
        cmd['revert'] = {}
        cmd['revert']['name']   = "vmxnet3_delete"
        cmd['revert']['descr']  = "delete vmxnet3 interface for %s" % pci
        cmd['revert']['params'] = { 'substs': [ { 'add_param':'sw_if_index', 'val_by_func':'dev_id_to_vpp_sw_if_index', 'arg':dev_id } ] }
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

