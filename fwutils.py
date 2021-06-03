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
import binascii
import datetime
import glob
import hashlib
import inspect
import ipaddress
import json
import os
import time
import platform
import subprocess
import psutil
import socket
import threading
import re
import fwglobals
import fwikev2
import fwnetplan
import fwstats
import shutil
import sys
import traceback
import yaml
from netaddr import IPNetwork, IPAddress
import threading
import serial

from tools.common.fw_vpp_startupconf import FwStartupConf

from fwapplications import FwApps
from fwrouter_cfg   import FwRouterCfg
from fwsystem_cfg   import FwSystemCfg
from fwmultilink    import FwMultilink
from fwpolicies     import FwPolicies
from fwwan_monitor  import get_wan_failover_metric
from fwikev2        import FwIKEv2


dpdk = __import__('dpdk-devbind')

def get_device_logs(file, num_of_lines):
    """Get device logs.

    :param file:            File name.
    :param num_of_lines:    Number of lines.

    :returns: Return list.
    """
    try:
        if not os.path.exists(file):
            return []

        cmd = "tail -{} {}".format(num_of_lines, file)
        res = subprocess.check_output(cmd, shell=True).decode().splitlines()

        # On zero matching, res is a list with a single empty
        # string which we do not want to return to the caller
        return res if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_device_packet_traces(num_of_packets, timeout):
    """Get device packet traces.

    :param num_of_packets:    Number of lines.
    :param timeout:           Timeout to wait for trace to complete.

    :returns: Array of traces.
    """
    try:
        cmd = 'sudo vppctl clear trace'
        subprocess.check_call(cmd, shell=True)
        cmd = 'sudo vppctl show vmxnet3'
        shif_vmxnet3 = subprocess.check_output(cmd, shell=True).decode()
        if shif_vmxnet3 is '':
            cmd = 'sudo vppctl trace add dpdk-input %s && sudo vppctl trace add virtio-input %s' % (num_of_packets, num_of_packets)
        else:
            cmd = 'sudo vppctl trace add vmxnet3-input %s && sudo vppctl trace add virtio-input %s' % (num_of_packets, num_of_packets)
        subprocess.check_call(cmd, shell=True)
        time.sleep(timeout)
        cmd = 'sudo vppctl show trace max {}'.format(num_of_packets)
        res = subprocess.check_output(cmd, shell=True).decode().splitlines()
        # skip first line (contains unnecessary information header)
        return res[1:] if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_device_versions(filename):
    """Get agent version.

    :param filename:           Versions file name.

    :returns: Version value.
    """
    try:
        with open(filename, 'r') as stream:
            versions = yaml.load(stream, Loader=yaml.BaseLoader)
            return versions
    except:
        err = "get_device_versions: failed to get versions: %s" % (format(sys.exc_info()[1]))
        fwglobals.log.error(err)
        return None

def get_machine_id():
    """Get machine id.

    :returns: UUID.
    """
    if fwglobals.g.cfg.UUID:    # If UUID is configured manually, use it
        return fwglobals.g.cfg.UUID

    try:                        # Fetch UUID from machine
        if platform.system()=="Windows":
            machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        else:
            machine_id = subprocess.check_output(['cat','/sys/class/dmi/id/product_uuid']).decode().split('\n')[0].strip()
        return machine_id.upper()
    except:
        return None

def get_machine_serial():
    """Get machine serial number.

    :returns: S/N string.
    """
    try:
        serial = subprocess.check_output(['dmidecode', '-s', 'system-serial-number']).decode().split('\n')[0].strip()
        return str(serial)
    except:
        return '0'
def pid_of(proccess_name):
    """Get pid of process.

    :param proccess_name:   Proccess name.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', proccess_name]).decode()
    except:
        pid = None
    return pid

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = pid_of('vpp')
    except:
        pid = None
    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    runs = True if vpp_pid() else False
    return runs

def get_vpp_tap_interface_mac_addr(dev_id):
    tap = dev_id_to_tap(dev_id)
    return get_interface_mac_addr(tap)

def get_interface_mac_addr(interface_name):
    interfaces = psutil.net_if_addrs()

    if interface_name in interfaces:
        addrs = interfaces[interface_name]
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                return addr.address

    return None

def af_to_name(af_type):
    """Convert socket type.

    :param af_type:        Socket type.

    :returns: String.
    """
    af_map = {
    	socket.AF_INET: 'IPv4',
    	socket.AF_INET6: 'IPv6',
    	psutil.AF_LINK: 'MAC',
	}
    return af_map.get(af_type, af_type)

def get_os_routing_table():
    """Get routing table.

    :returns: List of routes.
    """
    try:
        routing_table = subprocess.check_output(['route', '-n']).decode().split('\n')
        return routing_table
    except:
        return (None)

def get_default_route(if_name=None):
    """Get default route.

    :param if_name:  name of the interface to return info for.
        if not provided, the route with the lowest metric will return.

    :returns: tuple (<IP of GW>, <name of network interface>, <Dev ID of network interface>, <protocol>).
    """
    (via, dev, metric, proto) = ("", "", 0xffffffff, "")
    try:
        output = os.popen('ip route list match default').read()
        if output:
            routes = output.splitlines()
            for r in routes:
                _dev = ''   if not 'dev '    in r else r.split('dev ')[1].split(' ')[0]
                _via = ''   if not 'via '    in r else r.split('via ')[1].split(' ')[0]
                _metric = 0 if not 'metric ' in r else int(r.split('metric ')[1].split(' ')[0])
                _proto = '' if not 'proto '  in r else r.split('proto ')[1].split(' ')[0]

                if if_name == _dev: # If if_name specified, we return info for that dev even if it has a higher metric
                    dev    = _dev
                    via    = _via
                    metric = _metric
                    proto  = _proto
                    return (via, dev, get_interface_dev_id(dev), proto)

                if _metric < metric:  # The default route among default routes is the one with the lowest metric :)
                    dev    = _dev
                    via    = _via
                    metric = _metric
                    proto = _proto
    except:
        pass

    if not dev:
        return ("", "", "", "")

    dev_id = get_interface_dev_id(dev)
    return (via, dev, dev_id, proto)

def get_interface_gateway(if_name, if_dev_id=None):
    """Get gateway.

    :param if_name:  name of the interface, gateway for which is returned
    :param if_dev_id: Bus address of the interface, gateway for which is returned.
                     If provided, the 'if_name' is ignored. The name is fetched
                     from system by a Bus address.

    :returns: Gateway ip address.
    """
    if if_dev_id:
        if_name = dev_id_to_tap(if_dev_id)

    try:
        cmd   = "ip route list match default | grep via | grep 'dev %s'" % if_name
        route = os.popen(cmd).read()
        if not route:
            return '', ''
    except:
        return '', ''

    rip    = route.split('via ')[1].split(' ')[0]
    metric = '' if not 'metric ' in route else route.split('metric ')[1].split(' ')[0]
    return rip, metric


def get_tunnel_gateway(dst, dev_id):
    linux_interfaces = get_linux_interfaces()
    if linux_interfaces:
        interface = linux_interfaces.get(dev_id)
        if interface:
            try:
                network = interface['IPv4'] + '/' + interface['IPv4Mask']
                # If src and dst on the same network return an empty gw
                # In this case the system uses default route as a gateway and connect the interfaces directly and not via the GW
                if is_ip_in_subnet(dst,network): return ''
            except Exception as e:
                fwglobals.log.error("get_tunnel_gateway: failed to check networks: dst=%s, dev_id=%s, network=%s, error=%s" % (dst, dev_id, network, str(e)))

    # If src, dst are not on same subnet or any error, use the gateway defined on the device
    gw_ip, _ = get_interface_gateway('', if_dev_id=dev_id)
    return ipaddress.ip_address(gw_ip) if gw_ip else ipaddress.ip_address('0.0.0.0')

def is_interface_assigned_to_vpp(dev_id):
    """ Check if dev_id is assigned to vpp.
    This function could be called even deamon doesn't run.

    :params dev_id: Bus address to check if assigned

    : return : Boolean
    """
    if getattr(fwglobals.g, 'router_cfg', False):
        return len(fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)) > 0

    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        return len(router_cfg.get_interfaces(dev_id=dev_id)) > 0

    return False

def get_all_interfaces():
    """ Get all interfaces from linux. For dev id with address family of AF_INET,
        also store gateway, if exists.
        : return : Dictionary of dev_id->IP,GW
    """
    dev_id_ip_gw = {}
    interfaces = psutil.net_if_addrs()
    for nic_name, addrs in list(interfaces.items()):
        dev_id = get_interface_dev_id(nic_name)
        if not dev_id:
            continue

        if is_lte_interface(nic_name):
            tap_name = dev_id_to_tap(dev_id, check_vpp_state=True)
            if tap_name:
                nic_name = tap_name
                addrs = interfaces.get(nic_name)

        dev_id_ip_gw[dev_id] = {}
        dev_id_ip_gw[dev_id]['addr'] = ''
        dev_id_ip_gw[dev_id]['gw']   = ''
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address.split('%')[0]
                dev_id_ip_gw[dev_id]['addr'] = ip
                gateway, _ = get_interface_gateway(nic_name)
                dev_id_ip_gw[dev_id]['gw'] = gateway if gateway else ''
                break

    return dev_id_ip_gw

def get_interface_address(if_name, log=True, log_on_failure=None):
    """Gets IP address of interface by name found in OS.

    :param if_name:     Interface name.
    :param log:         If True the found/not found address will be logged.
                        Errors or debug info is printed in any case.
    :param log_on_failure: If provided, overrides the 'log' in case of not found address.

    :returns: IP address.
    """
    if log_on_failure == None:
        log_on_failure = log

    interfaces = psutil.net_if_addrs()
    if if_name not in interfaces:
        fwglobals.log.debug("get_interface_address(%s): interfaces: %s" % (if_name, str(interfaces)))
        return None

    addresses = interfaces[if_name]
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip   = addr.address
            mask = IPAddress(addr.netmask).netmask_bits()
            if log:
                fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addr)))
            return '%s/%s' % (ip, mask)

    if log_on_failure:
        fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addresses)))
    return None

def get_interface_name(ip_no_mask):
    """ Get interface name based on IP address

    : param ip_no_mask: ip address with no mask
    : returns : if_name - interface name
    """
    interfaces = psutil.net_if_addrs()
    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family == socket.AF_INET and address.address == ip_no_mask:
                return if_name
    return None

def is_ip_in_subnet(ip, subnet):
    """Check if IP address is in subnet.

    :param ip:            IP address.
    :param subnet:        Subnet address.

    :returns: 'True' if address is in subnet.
    """
    return True if IPAddress(ip) in IPNetwork(subnet) else False

def dev_id_to_full(dev_id):
    """Convert short PCI into full representation.
    the 'dev_id' param could be either a pci or a usb address.
    in case of pci address - the function will convert into a full address

    :param dev_id:      device bus address.

    :returns: full device bus address.
    """
    (addr_type, addr) = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return dev_id

    pc = addr.split('.')
    if len(pc) == 2:
        return dev_id_add_type(pc[0]+'.'+"%02x"%(int(pc[1],16)))
    return dev_id

# Convert 0000:00:08.01 provided by management to 0000:00:08.1 used by Linux
def dev_id_to_short(dev_id):
    """Convert full PCI into short representation.
    the 'dev_id' param could be either a pci or a usb address.
    in case of pci address - convert pci provided by management into a short address used by Linux

    :param dev_id:      Full PCI address.

    :returns: Short PCI address.
    """
    addr_type, addr = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return dev_id

    l = addr.split('.')
    if len(l[1]) == 2 and l[1][0] == '0':
        return dev_id_add_type(l[0] + '.' + l[1][1])
    return dev_id

def dev_id_parse(dev_id):
    """Convert a dev id into a tuple contained address type (pci, usb) and address.

    :param dev_id:     device bus address.

    :returns: Tuple (type, address)
    """
    type_and_addr = dev_id.split(':', 1)
    if type_and_addr and len(type_and_addr) == 2:
        return (type_and_addr[0], type_and_addr[1])

    return ("", "")

def dev_id_add_type(dev_id):
    """Add address type at the begining of the address.

    :param dev_id:      device bus address.

    :returns: device bus address with type.
    """

    if dev_id:
        if dev_id.startswith('pci:') or dev_id.startswith('usb:'):
            return dev_id

        if re.search('usb', dev_id):
            return 'usb:%s' % dev_id

        return 'pci:%s' % dev_id

    return ''

def set_linux_interfaces_stun(dev_id, public_ip, public_port, nat_type):
    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces.get(dev_id)
        if interface:
            interface['public_ip']   = public_ip
            interface['public_port'] = public_port
            interface['nat_type']    = nat_type

def clear_linux_interfaces_cache():
    with fwglobals.g.cache.lock:
        fwglobals.g.cache.linux_interfaces.clear()

def get_linux_interfaces(cached=True):
    """Fetch interfaces from Linux.

    :param cached: if True the data will be fetched from cache.

    :return: Dictionary of interfaces by full form dev id.
    """
    with fwglobals.g.cache.lock:

        interfaces = fwglobals.g.cache.linux_interfaces

        if cached and interfaces:
            return copy.deepcopy(interfaces)

        fwglobals.log.debug("get_linux_interfaces: Start to build Linux interfaces cache")
        interfaces.clear()

        linux_inf = psutil.net_if_addrs()
        for (if_name, addrs) in list(linux_inf.items()):

            dev_id = get_interface_dev_id(if_name)
            if not dev_id:
                continue

            interface = {
                'name':             if_name,
                'devId':            dev_id,
                'driver':           get_interface_driver(if_name, False),
                'MAC':              '',
                'IPv4':             '',
                'IPv4Mask':         '',
                'IPv6':             '',
                'IPv6Mask':         '',
                'dhcp':             '',
                'gateway':          '',
                'metric':           '',
                'internetAccess':   '',
                'public_ip':        '',
                'public_port':      '',
                'nat_type':         '',
            }

            interface['dhcp'] = fwnetplan.get_dhcp_netplan_interface(if_name)
            interface['gateway'], interface['metric'] = get_interface_gateway(if_name)

            for addr in addrs:
                addr_af_name = af_to_name(addr.family)
                if not interface[addr_af_name]:
                    interface[addr_af_name] = addr.address.split('%')[0]
                    if addr.netmask != None:
                        interface[addr_af_name + 'Mask'] = (str(IPAddress(addr.netmask).netmask_bits()))

            if is_wifi_interface(if_name):
                interface['deviceType'] = 'wifi'
                interface['deviceParams'] = wifi_get_capabilities(dev_id)

            if is_lte_interface(if_name):
                interface['deviceType'] = 'lte'
                interface['dhcp'] = 'yes'
                interface['deviceParams'] = {
                    'initial_pin1_state': lte_get_pin_state(dev_id),
                    'default_settings':   lte_get_default_settings(dev_id)
                }

                # LTE physical device has no IP, GW etc. so we take this info from vppsb interface (vpp1)
                tap_name = dev_id_to_tap(dev_id, check_vpp_state=True)
                if tap_name:
                    interface['gateway'], interface['metric'] = get_interface_gateway(tap_name)
                    int_addr = get_interface_address(tap_name)
                    if int_addr:
                        int_addr = int_addr.split('/')
                        interface['IPv4'] = int_addr[0]
                        interface['IPv4Mask'] = int_addr[1]

            # Add information specific for WAN interfaces
            #
            if interface['gateway']:

                # Fetch public address info from STUN module
                #
                interface['public_ip'], interface['public_port'], interface['nat_type'] = \
                    fwglobals.g.stun_wrapper.find_addr(dev_id)

                # Fetch internet connectivity info from WAN Monitor module.
                # Hide the metric watermarks used for WAN failover from flexiManage.
                #
                metric = 0 if not interface['metric'] else int(interface['metric'])
                if metric >= fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK:
                    interface['metric'] = str(metric - fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK)
                    interface['internetAccess'] = False
                elif not interface['IPv4']:       # If DHCP interface has no IP
                    interface['internetAccess'] = False
                else:
                    interface['internetAccess'] = True
            else:
                interface['internetAccess'] = False  # If interface has no GW

            interfaces[dev_id] = interface

        fwglobals.log.debug("get_linux_interfaces: Finished to build Linux interfaces cache")
        return copy.deepcopy(interfaces)

def get_interface_dev_id(if_name):
    """Convert  interface name into bus address.

    :param if_name:      Linux interface name.

    :returns: dev_id.
    """
    if not if_name:
        return ''

    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)
        if not interface:
            fwglobals.g.cache.linux_interfaces_by_name[if_name] = {}
            interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)

        dev_id = interface.get('dev_id')
        if dev_id != None:
            return dev_id

        # First try to get dev id if interface is under linux control
        dev_id = build_interface_dev_id(if_name)
        if dev_id:
            interface.update({'dev_id': dev_id})
            return dev_id

        if not vpp_does_run():
            # don't update cache
            return ''

        # If not found and vpp is running, try to fetch dev id if interface was created by vppsb, e.g. vpp1
        vpp_if_name = tap_to_vpp_if_name(if_name)
        if not vpp_if_name:
            # don't update cache
            return ''

        if re.match(r'^loop', vpp_if_name): # loopback interfaces have no dev id (bus id)
            interface.update({'dev_id': ''})
            return ''

        dev_id = vpp_if_name_to_dev_id(vpp_if_name)
        if dev_id:
            interface.update({'dev_id': dev_id})
            return dev_id

        fwglobals.log.error(
            'get_interface_dev_id: if_name=%s, vpp_if_name=%s' % (if_name, str(vpp_if_name)))
        # don't update cache
        return ''

def build_interface_dev_id(linux_dev_name, sys_class_net=None):
    """Converts Linux interface name into bus address.
    This function returns dev_id only for physical interfaces controlled by linux.

    :param linux_dev_name:     Linux device name.
    :param sys_class_net:      List of available networking devices formatted as output of the 'ls -l /sys/class/net' command.
                               This parameter is used for tests.

    :returns: dev_id or None if interface was created by vppsb
    """
    if not linux_dev_name:
        return ""

    if sys_class_net is None:
        cmd = "sudo ls -l /sys/class/net"
        try:
            out = subprocess.check_output(cmd, shell=True).decode()
            sys_class_net = out.splitlines()
        except Exception as e:
            fwglobals.log.error('build_interface_dev_id: failed to fetch networking devices: %s' % str(e))
            return ""

    for networking_device in sys_class_net:
        regex = r'\b%s\b' % linux_dev_name
        if not re.search(regex, networking_device):
            continue
        regex = r'[0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{1,2}|usb\d+\/.*(?=\/net)'
        if_addr = re.findall(regex, networking_device)
        if if_addr:
            if_addr = if_addr[-1]
            if re.search(r'usb|pci', networking_device):
                dev_id = dev_id_add_type(if_addr)
                dev_id = dev_id_to_full(dev_id)
                return dev_id

    return ""

def dev_id_to_linux_if(dev_id):
    """Convert device bus address into Linux interface name.

    :param dev_id:      device bus address.

    :returns: Linux interface name.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/class/net/
    # total 0
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s8 -> ../../devices/pci0000:00/0000:00:08.0/net/enp0s8
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s9 -> ../../devices/pci0000:00/0000:00:09.0/net/enp0s9
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 lo -> ../../devices/virtual/net/lo

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    dev_id = dev_id_to_short(dev_id)
    _, addr = dev_id_parse(dev_id)

    try:
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + addr, shell=True).decode()
    except:
        return None
    if output is None:
        return None
    return output.rstrip().split('/')[-1]

def dev_id_is_vmxnet3(dev_id):
    """Check if device bus address is vmxnet3.

    :param dev_id:    device bus address.

    :returns: 'True' if it is vmxnet3, 'False' otherwise.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/bus/pci/devices/*/driver
    # lrwxrwxrwx 1 root root 0 Jul 17 22:08 /sys/bus/pci/devices/0000:03:00.0/driver -> ../../../../bus/pci/drivers/vmxnet3
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:0b:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:13:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci

    # We get pci:0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    dev_id = dev_id_to_short(dev_id)
    addr_type, addr = dev_id_parse(dev_id)
    if addr_type == 'usb':
        return False

    try:
        # The 'ls -l /sys/bus/pci/devices/*/driver' approach doesn't work well.
        # When vpp starts, it rebinds device to vfio-pci, so 'ls' doesn't detect it.
        # Therefore we go with dpdk-devbind.py. It should be installed on Linux
        # as a part of flexiwan-router installation.
        # When vpp does not run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vmxnet3 unused=vfio-pci,uio_pci_generic
        # When vpp does run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vfio-pci unused=vmxnet3,uio_pci_generic
        #
        #output = subprocess.check_output("sudo ls -l /sys/bus/pci/devices/%s/driver | grep vmxnet3" % pci, shell=True).decode()
        output = subprocess.check_output("sudo dpdk-devbind -s | grep -E '%s .*vmxnet3'" % addr, shell=True).decode()
    except:
        return False
    if output is None:
        return False
    return True

# 'dev_id_to_vpp_if_name' function maps interface referenced by device bus address - pci or usb - eg. '0000:00:08.00'
# into name of interface in VPP, eg. 'GigabitEthernet0/8/0'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def dev_id_to_vpp_if_name(dev_id):
    """Convert interface bus address into VPP interface name.

    :param dev_id:      device bus address.

    :returns: VPP interface name.
    """
    dev_id = dev_id_to_full(dev_id)
    vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id)
    if vpp_if_name: return vpp_if_name
    else: return _build_dev_id_to_vpp_if_name_maps(dev_id, None)

# 'vpp_if_name_to_dev_id' function maps interface name, eg. 'GigabitEthernet0/8/0'
# into the dev id of that interface, eg. '0000:00:08.00'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def vpp_if_name_to_dev_id(vpp_if_name):
    """Convert vpp interface name address into interface bus address.

    :param vpp_if_name:      VPP interface name.

    :returns: Interface bus address.
    """
    dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id.get(vpp_if_name)
    if dev_id: return dev_id
    else: return _build_dev_id_to_vpp_if_name_maps(None, vpp_if_name)

# '_build_dev_id_to_vpp_if_name_maps' function build the local caches of
# device bus address to vpp_if_name and vise vera
# if dev_id provided, return the name found for this dev_id,
# else, if name provided, return the dev_id for this name,
# else, return None
# To do that we dump all hardware interfaces, split the dump into list by empty line,
# and search list for interface that includes the dev_id name.
# The dumps brings following table:
#              Name                Idx    Link  Hardware
# GigabitEthernet0/8/0               1    down  GigabitEthernet0/8/0
#   Link speed: unknown
#   ...
#   pci: device 8086:100e subsystem 8086:001e address 0000:00:08.00 numa 0
#
def _build_dev_id_to_vpp_if_name_maps(dev_id, vpp_if_name):

    # Note, tap interfaces created by "create tap" are handled as follows:
    # the commands "create tap host-if-name tap_wwan0" and "enable tap-inject" create three interfaces:
    # Two on Linux (tap_wwan0, vpp1) and one on vpp (tap1).
    # Note, we use "tap_" prefix in "tap_wwan0" in order to be able to associate the wwan0 physical interface
    # with the tap1 interface. This is done as follows:
    # Then we can substr the dev_name and get back the linux interface name. Then we can get the dev_id of this interface.
    #
    taps = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_tap_v2_dump()
    for tap in taps:
        vpp_tap = tap.dev_name                      # fetch tap0
        linux_tap = tap.host_if_name                # fetch tap_wwan0
        linux_dev_name = linux_tap.split('_')[-1]   # tap_wwan0 - > wwan0

        # if the lte/wifi interface name is long (more than 15 letters),
        # It's not enough to slice tap_wwan0 and get the linux interface name from the last part.
        # So we take it from the /sys/class/net by filter out the tap_wwan0,
        # then we can get the complete name
        #
        cmd =  "ls -l /sys/class/net | grep -v %s | grep %s" % (linux_tap, linux_dev_name)
        linux_dev_name = subprocess.check_output(cmd, shell=True).decode().strip().split('/')[-1]

        bus = build_interface_dev_id(linux_dev_name)            # fetch bus address of wwan0
        if bus:
            fwglobals.g.cache.dev_id_to_vpp_if_name[bus] = vpp_tap
            fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_tap] = bus

    shif = _vppctl_read('show hardware-interfaces')
    if shif == None:
        fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps: Error reading interface info")
    data = shif.splitlines()
    for interface in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        data = ''.join(interface)
        (k,v) = _parse_vppname_map(data,
            valregex=r"^(\w[^\s]+)\s+\d+\s+(\w+)",
            keyregex=r"\s+pci:.*\saddress\s(.*?)\s")
        if k and v:
            k = dev_id_add_type(k)
            full_addr = dev_id_to_full(k)
            fwglobals.g.cache.dev_id_to_vpp_if_name[full_addr] = v
            fwglobals.g.cache.vpp_if_name_to_dev_id[v] = full_addr

    vmxnet3hw = fwglobals.g.router_api.vpp_api.vpp.api.vmxnet3_dump()
    for hw_if in vmxnet3hw:
        vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
        pci_addr = 'pci:%s' % pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.cache.dev_id_to_vpp_if_name[pci_addr] = vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name] = pci_addr

    if dev_id:
        vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id)
        if vpp_if_name: return vpp_if_name
    elif vpp_if_name:
        dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id.get(vpp_if_name)
        if dev_id: return dev_id

    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: sh hard: %s" % (dev_id, vpp_if_name, shif))
    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: sh vmxnet3: %s" % (dev_id, vpp_if_name, vmxnet3hw))
    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found: %s" % (dev_id, vpp_if_name, str(traceback.extract_stack())))
    return None

# 'pci_str_to_bytes' converts "0000:0b:00.0" string to bytes to pack following struct:
#    struct
#    {
#      u16 domain;
#      u8 bus;
#      u8 slot: 5;
#      u8 function:3;
#    };
#
def pci_str_to_bytes(pci_str):
    """Convert PCI address into bytes.

    :param pci_str:      PCI address.

    :returns: Bytes array.
    """
    list = re.split(r':|\.', pci_str)
    domain   = int(list[0], 16)
    bus      = int(list[1], 16)
    slot     = int(list[2], 16)
    function = int(list[3], 16)
    bytes = ((domain & 0xffff) << 16) | ((bus & 0xff) << 8) | ((slot & 0x1f) <<3 ) | (function & 0x7)
    return socket.htonl(bytes)   # vl_api_vmxnet3_create_t_handler converts parameters by ntoh for some reason (vpp\src\plugins\vmxnet3\vmxnet3_api.c)

# 'pci_str_to_bytes' converts pci bytes into full string "0000:0b:00.0"
def pci_bytes_to_str(pci_bytes):
    """Converts PCI bytes to PCI full string.

    :param pci_str:      PCI bytes.

    :returns: PCI full string.
    """
    bytes = socket.ntohl(pci_bytes)
    domain   = (bytes >> 16)
    bus      = (bytes >> 8) & 0xff
    slot     = (bytes >> 3) & 0x1f
    function = (bytes) & 0x7
    return "%04x:%02x:%02x.%02x" % (domain, bus, slot, function)

# 'dev_id_to_vpp_sw_if_index' function maps interface referenced by device bus address, e.g pci - '0000:00:08.00'
# into index of this interface in VPP, eg. 1.
# To do that we convert firstly the device bus address into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0', than we dump all VPP interfaces and search for interface
# with this name. If found - return interface index.

def dev_id_to_vpp_sw_if_index(dev_id):
    """Convert device bus address into VPP sw_if_index.

    :param dev_id:      device bus address.

    :returns: sw_if_index.
    """
    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    fwglobals.log.debug("dev_id_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (dev_id, str(vpp_if_name)))
    if vpp_if_name is None:
        return None

    sw_ifs = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump()
    for sw_if in sw_ifs:
        if re.match(vpp_if_name, sw_if.interface_name):    # Use regex, as sw_if.interface_name might include trailing whitespaces
            return sw_if.sw_if_index
    fwglobals.log.debug("dev_id_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (dev_id, yaml.dump(sw_ifs, canonical=True)))

    return None

# 'dev_id_to_tap' function maps interface referenced by dev_id, e.g '0000:00:08.00'
# into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp1.
# To do that we convert firstly the dev_id into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0' and than we grep output of 'vppctl sh tap-inject'
# command by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def dev_id_to_tap(dev_id, check_vpp_state=False):
    """Convert Bus address into TAP name.

    :param dev_id:          Bus address.
    :param check_vpp_state: If True ensure that vpp runs so taps are available.
    :returns: Linux TAP interface name.
    """

    if check_vpp_state:
        is_assigned = is_interface_assigned_to_vpp(dev_id)
        if not (is_assigned and vpp_does_run()):
            return None

    dev_id_full = dev_id_to_full(dev_id)
    cache    = fwglobals.g.cache.dev_id_to_vpp_tap_name

    tap = cache.get(dev_id_full)

    if tap:
        return tap

    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    if vpp_if_name is None:
        return None
    tap = vpp_if_name_to_tap(vpp_if_name)
    if tap:
        cache[dev_id_full] = tap
    return tap

# 'tap_to_vpp_if_name' function maps name of vpp tap interface in Linux, e.g. vpp0,
# into name of the vpp interface.
# To do that it greps output of 'vppctl sh tap-inject' by the tap interface name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def tap_to_vpp_if_name(tap):
    """Convert Linux interface created by tap-inject into VPP interface name.

     :param tap:  Interface created in linux by tap-inject.

     :returns: Vpp interface name.
     """
    taps = _vppctl_read("show tap-inject")

    if taps is None:
        raise Exception("tap_to_vpp_if_name: failed to fetch tap info from VPP")

    taps = taps.splitlines()
    for line in taps:
        # check if tap-inject is configured and enabled
        if ' -> ' not in line:
            fwglobals.log.debug("tap_to_vpp_if_name: vpp was not started yet ('%s')" % line)
            break

        tap_info = line.split(' -> ')
        if tap_info[1] == tap:
            return tap_info[0]

    return None


# 'vpp_if_name_to_tap' function maps name of interface in VPP, e.g. loop0,
# into name of correspondent tap interface in Linux.
# To do that it greps output of 'vppctl sh tap-inject' by the interface name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
#       loop0 -> vpp2
def vpp_if_name_to_tap(vpp_if_name):
    """Convert VPP interface name into Linux TAP interface name.

     :param vpp_if_name:  interface name.

     :returns: Linux TAP interface name.
     """
    # vpp_api.cli() throw exception in vpp 19.01 (and works in vpp 19.04)
    # taps = fwglobals.g.router_api.vpp_api.cli("show tap-inject")
    taps = _vppctl_read("show tap-inject")
    if taps is None:
        raise Exception("vpp_if_name_to_tap: failed to fetch tap info from VPP")

    pattern = '%s -> ([a-zA-Z0-9_]+)' % vpp_if_name
    match = re.search(pattern, taps)
    if match is None:
        return None
    tap = match.group(1)
    return tap

def generate_linux_interface_short_name(prefix, linux_if_name, max_length=15):
    """
    The interface name in Linux cannot be more than 15 letters.
    So, we calculate the length of the prefix plus the interface name.
    If they are more the 15 letters, we cutting the needed letters from the beginning of the Linux interface name.
    We cut from the begging because the start of the interface name might be the same as other interfaces (eth1, eth2),
    They usually different by the end of the name

    :param prefix: prefix to add to the interface name

    :param linux_if_name: name of the linux interface to create interface for

    :returns: interface name to use.
    """
    new_name = '%s_%s' % (prefix, linux_if_name)
    if len(new_name) > max_length:
        letters_to_cat = len(new_name) - 15
        new_name = '%s_%s' % (prefix, linux_if_name[letters_to_cat:])
    return new_name

def linux_tap_by_interface_name(linux_if_name):
    try:
        lines = subprocess.check_output("sudo ip link | grep %s" % generate_linux_interface_short_name("tap", linux_if_name), shell=True).decode().splitlines()
        for line in lines:
            words = line.split(': ')
            return words[1]
    except:
        return None

def vpp_tap_connect(linux_tap_if_name):
    """Run vpp tap connect command.
      This command will create a linux tap interface and also tapcli interface in vpp.
     :param linux_tap_if_name: name to be assigned to linux tap device

     :returns: VPP tap interface name.
     """

    vppctl_cmd = "tap connect %s" % linux_tap_if_name
    fwglobals.log.debug("vppctl " + vppctl_cmd)
    subprocess.check_call("sudo vppctl %s" % vppctl_cmd, shell=True)

def vpp_add_static_arp(dev_id, gw, mac):
    try:
        vpp_if_name = dev_id_to_vpp_if_name(dev_id)
        vppctl_cmd = "set ip neighbor static %s %s %s" % (vpp_if_name, gw, mac)
        fwglobals.log.debug("vppctl " + vppctl_cmd)
        subprocess.check_call("sudo vppctl %s" % vppctl_cmd, shell=True)
        return (True, None)
    except Exception as e:
        return (False, "Failed to add static arp in vpp for dev_id: %s\nOutput: %s" % (dev_id, str(e)))

def vpp_sw_if_index_to_name(sw_if_index):
    """Convert VPP sw_if_index into VPP interface name.

     :param sw_if_index:      VPP sw_if_index.

     :returns: VPP interface name.
     """
    name = ''

    for sw_if in fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump():
        if sw_if_index == sw_if.sw_if_index:
            name = sw_if.interface_name.rstrip(' \t\r\n\0')

    return name

# 'sw_if_index_to_tap' function maps sw_if_index assigned by VPP to some interface,
# e.g '4' into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp2.
# To do that we dump all interfaces from VPP, find the one with the provided index,
# take its name, e.g. loop0, and grep output of 'vppctl sh tap-inject' by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
#       loop0 -> vpp2
def vpp_sw_if_index_to_tap(sw_if_index):
    """Convert VPP sw_if_index into Linux TAP interface name.

     :param sw_if_index:      VPP sw_if_index.

     :returns: Linux TAP interface name.
     """
    return vpp_if_name_to_tap(vpp_sw_if_index_to_name(sw_if_index))

def vpp_ip_to_sw_if_index(ip):
    """Convert ip address into VPP sw_if_index.

     :param ip: IP address.

     :returns: sw_if_index.
     """
    network = IPNetwork(ip)

    for sw_if in fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump():
        tap = vpp_sw_if_index_to_tap(sw_if.sw_if_index)
        if tap:
            int_address_str = get_interface_address(tap)
            if not int_address_str:
                continue
            int_address = IPNetwork(int_address_str)
            if network == int_address:
                return sw_if.sw_if_index

def _vppctl_read(cmd, wait=True):
    """Read command from VPP.

    :param cmd:       Command to execute (not including vppctl).
    :param wait:      Whether to wait until command succeeds.

    :returns: Output returned bu vppctl.
    """
    retries = 200
    retries_sleep = 1
    if wait == False:
        retries = 1
        retries_sleep = 0
    # make sure socket exists
    for _ in range(retries):
        if os.path.exists("/run/vpp/cli.sock"):
            break
        time.sleep(retries_sleep)
    if not os.path.exists("/run/vpp/cli.sock"):
        return None
    # make sure command succeeded, try up to 200 iterations
    for _ in range(retries):
        try:
            _ = open(os.devnull, 'r+b', 0)
            handle = os.popen('sudo vppctl ' + cmd + ' 2>/dev/null')
            data = handle.read()
            retcode = handle.close()
            if retcode == None or retcode == 0:  # Exit OK
                break
        except:
            return None
        time.sleep(retries_sleep)
    if retcode: # not succeeded after 200 retries
        return None
    return data

def _parse_vppname_map(s, valregex, keyregex):
    """Find key and value in a string using regex.

    :param s:               String.
    :param valregex:        Value.
    :param keyregex:        Key.

    :returns: Error message and status code.
    """
    # get value
    r = re.search(valregex,s)
    if r!=None: val_data = r.group(1)
    else: return (None, None)   # val not found, don't add and return
    # get key
    r = re.search(keyregex,s)
    if r!=None: key_data = r.group(1)
    else: return (None, None)   # key not found, don't add and return
    # Return values
    return (key_data, val_data)

def stop_vpp():
    """Stop VPP and rebind Linux interfaces.

     :returns: Error message and status code.
     """
    dpdk_ifs = []
    dpdk.devices = {}
    dpdk.dpdk_drivers = ["igb_uio", "vfio-pci", "uio_pci_generic"]
    dpdk.check_modules()
    dpdk.get_nic_details()
    os.system('sudo systemctl stop vpp')
    os.system('sudo systemctl stop frr')
    for d,v in list(dpdk.devices.items()):
        if "Driver_str" in v:
            if v["Driver_str"] in dpdk.dpdk_drivers:
                dpdk.unbind_one(v["Slot"], False)
                dpdk_ifs.append(d)
        elif "Module_str" != "":
            dpdk_ifs.append(d)
    # refresh nic_details
    dpdk.get_nic_details()
    for d in dpdk_ifs:
        drivers_unused = dpdk.devices[d]["Module_str"].split(',')
        #print ("Drivers unused=" + str(drivers_unused))
        for drv in drivers_unused:
            #print ("Driver=" + str(drv))
            if drv not in dpdk.dpdk_drivers:
                dpdk.bind_one(dpdk.devices[d]["Slot"], drv, False)
                break
    fwstats.update_state(False)
    netplan_apply('stop_vpp')
    with FwIKEv2() as ike:
        ike.clean()

def reset_device_config():
    """Reset router config by cleaning DB and removing config files.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        router_cfg.clean()
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        system_cfg.clean()
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        os.remove(fwglobals.g.ROUTER_STATE_FILE)
    if os.path.exists(fwglobals.g.FRR_OSPFD_FILE):
        os.remove(fwglobals.g.FRR_OSPFD_FILE)
    if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_BACKUP, fwglobals.g.VPP_CONFIG_FILE)
    elif os.path.exists(fwglobals.g.VPP_CONFIG_FILE_RESTORE):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE)
    if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
        os.remove(fwglobals.g.CONN_FAILURE_FILE)
    with FwApps(fwglobals.g.APP_REC_DB_FILE) as db_app_rec:
        db_app_rec.clean()
    with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
        db_multilink.clean()
    with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
        db_policies.clean()

    fwnetplan.restore_linux_netplan_files()
    with FwIKEv2() as ike:
        ike.clean()

    if 'lte' in fwglobals.g.db:
        fwglobals.g.db['lte'] = {}

    reset_dhcpd()

def print_system_config(full=False):
    """Print router configuration.

     :returns: None.
     """
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        cfg = system_cfg.dumps(full=full)
        print(cfg)

def print_device_config_signature():
    cfg = get_device_config_signature()
    print(cfg)

def print_router_config(basic=True, full=False, multilink=False):
    """Print router configuration.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        if basic:
            cfg = router_cfg.dumps(full=full, escape=['add-application','add-multilink-policy'])
        elif multilink:
            cfg = router_cfg.dumps(full=full, types=['add-application','add-multilink-policy'])
        else:
            cfg = ''
        print(cfg)

def print_general_database():
    out = []
    try:
        for key in sorted(list(fwglobals.g.db.keys())):
            obj = {}
            obj[key] = fwglobals.g.db[key]
            out.append(obj)
        cfg = json.dumps(out, indent=2, sort_keys=True)
        print(cfg)
    except Exception as e:
        fwglobals.log.error(str(e))
        pass
    
def update_device_config_signature(request):
    """Updates the database signature.
    This function assists the database synchronization feature that keeps
    the configuration set by user on the flexiManage in sync with the one
    stored on the flexiEdge device.
        The initial signature of the database is empty string. Than on every
    successfully handled request it is updated according following formula:
            signature = sha1(signature + request)
    where both signature and delta are strings.

    :param request: the last successfully handled router configuration
                    request, e.g. add-interface, remove-tunnel, etc.
                    As configuration database signature should reflect
                    the latest configuration, it should be updated with this
                    request.
    """
    current     = fwglobals.g.db['signature']
    delta       = json.dumps(request, separators=(',', ':'), sort_keys=True)
    update      = current + delta
    hash_object = hashlib.sha1(update.encode())
    new         = hash_object.hexdigest()

    fwglobals.g.db['signature'] = new
    fwglobals.log.debug("sha1: new=%s, current=%s, delta=%s" %
                        (str(new), str(current), str(delta)))

def get_device_config_signature():
    if not 'signature' in fwglobals.g.db:
        reset_device_config_signature()
    return fwglobals.g.db['signature']

def reset_device_config_signature(new_signature=None, log=True):
    """Resets configuration signature to the empty sting.

    :param new_signature: string to be used as a signature of the configuration.
            If not provided, the empty string will be used.
            When flexiManage detects discrepancy between this signature
            and between signature that it calculated, it sends
            the 'sync-device' request in order to apply the user
            configuration onto device. On successfull sync the signature
            is reset to the empty string on both sides.
    :param log: if False the reset will be not logged.
    """
    old_signature = fwglobals.g.db.get('signature', '<none>')
    new_signature = "" if new_signature == None else new_signature
    fwglobals.g.db['signature'] = new_signature
    if log:
        fwglobals.log.debug("reset signature: '%s' -> '%s'" % \
                            (old_signature, new_signature))

def dump_router_config(full=False):
    """Dumps router configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of 'add-X' requests.
    """
    cfg = []
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        cfg = router_cfg.dump(full)
    return cfg

def dump_system_config(full=False):
    """Dumps system configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of 'add-X' requests.
    """
    cfg = []
    with FwSystemCfg(fwglobals.g.SYSTEM_CFG_FILE) as system_cfg:
        cfg = system_cfg.dump(full)
    return cfg

def get_router_state():
    """Check if VPP is running.

     :returns: VPP state.
     """
    reason = ''
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        state = 'failed'
        with open(fwglobals.g.ROUTER_STATE_FILE, 'r') as f:
            reason = f.read()
    elif vpp_pid():
        state = 'running'
    else:
        state = 'stopped'
    return (state, reason)

def _get_group_delimiter(lines, delimiter):
    """Helper function to iterate through a group lines by delimiter.

    :param lines:       List of text lines.
    :param delimiter:   Regex to group lines by.

    :returns: None.
    """
    data = []
    for line in lines:
        if re.match(delimiter,line)!=None:
            if data:
                yield data
                data = []
        data.append(line)
    if data:
        yield data

def _parse_add_if(s, res):
    """Helper function that parse fields from a given interface data and add to res.

    :param s:       String with interface data.
    :param res:     Dict to store the result in.

    :returns: None.
    """
    # get interface name
    r = re.search(r"^(\w[^\s]+)\s+\d+\s+(\w+)",s)
    if r!=None and r.group(2)=="up": if_name = r.group(1)
    else: return    # Interface not found, don't add and return
    # rx packets
    r = re.search(r" rx packets\s+(\d+)?",s)
    if r!=None: rx_packets = r.group(1)
    else: rx_packets = 0
    # tx packets
    r = re.search(r" tx packets\s+(\d+)?",s)
    if r!=None: tx_packets = r.group(1)
    else: tx_packets = 0
    # rx bytes
    r = re.search(r" rx bytes\s+(\d+)?",s)
    if r!=None: rx_bytes = r.group(1)
    else: rx_bytes = 0
    # tx bytes
    r = re.search(r" tx bytes\s+(\d+)?",s)
    if r!=None: tx_bytes = r.group(1)
    else: tx_bytes = 0
    # Add data to res
    res[if_name] = {'rx_pkts':int(rx_packets), 'tx_pkts':int(tx_packets), 'rx_bytes':int(rx_bytes), 'tx_bytes':int(tx_bytes)}

def get_vpp_if_count():
    """Get number of VPP interfaces.

     :returns: Dictionary with results.
     """
    shif = _vppctl_read('sh int', wait=False)
    if shif == None:  # Exit with an error
        return None
    data = shif.splitlines()
    res = {}
    for interface in _get_group_delimiter(data, r"^\w.*?\s"):
        # Contains data for a given interface
        data = ''.join(interface)
        _parse_add_if(data, res)
    return res

def ip_str_to_bytes(ip_str):
    """Convert IP address string into bytes.

     :param ip_str:         IP address string.

     :returns: IP address in bytes representation.
     """
    # take care of possible netmask, like in 192.168.56.107/24
    addr_ip = ip_str.split('/')[0]
    addr_len = int(ip_str.split('/')[1]) if len(ip_str.split('/')) > 1 else 32
    return socket.inet_pton(socket.AF_INET, addr_ip), addr_len

def mac_str_to_bytes(mac_str):      # "08:00:27:fd:12:01" -> bytes
    """Convert MAC address string into bytes.

     :param mac_str:        MAC address string.

     :returns: MAC address in bytes representation.
     """
    return binascii.a2b_hex(mac_str.replace(':', ''))

def is_python2():
    """Checks if it is Python 2 version.

     :returns: 'True' if Python2 and 'False' otherwise.
     """
    ret = True if sys.version_info < (3, 0) else False
    return ret

def hex_str_to_bytes(hex_str):
    """Convert HEX string into bytes.

     :param hex_str:        HEX string.

     :returns: Bytes array.
     """
    if is_python2():
        return hex_str.decode("hex")
    else:
        return bytes.fromhex(hex_str)

def yaml_dump(var):
    """Convert object into YAML string.

    :param var:        Object.

    :returns: YAML string.
    """
    str = yaml.dump(var, canonical=True)
    str = re.sub(r"\n[ ]+: ", ' : ', str)
    return str

#
def valid_message_string(str):
    """Ensure that string contains only allowed by management characters.
    To mitigate security risks management limits text that might be received
    within responses to the management-to-device requests.
    This function ensure the compliance of string to the management requirements.

    :param str:        String.

    :returns: 'True' if valid and 'False' otherwise.
    """
    if len(str) > 200:
        fwglobals.log.excep("valid_message_string: string is too long")
        return False
    # Enable following characters only: [0-9],[a-z],[A-Z],'-','_',' ','.',':',',', etc.
    tmp_str = re.sub(r'[-_.,:0-9a-zA-Z_" \']', '', str)
    if len(tmp_str) > 0:
        fwglobals.log.excep("valid_message_string: string has not allowed characters")
        return False
    return True

def obj_dump(obj, print_obj_dir=False):
    """Print object fields and values. Used for debugging.

     :param obj:                Object.
     :param print_obj_dir:      Print list of attributes and methods.

     :returns: None.
     """
    callers_local_vars = list(inspect.currentframe().f_back.f_locals.items())
    obj_name = [var_name for var_name, var_val in callers_local_vars if var_val is obj][0]
    print('========================== obj_dump start ==========================')
    print("obj=%s" % obj_name)
    print("str(%s): %s" % (obj_name, str(obj)))
    if print_obj_dir:
        print("dir(%s): %s" % (obj_name, str(dir(obj))))
    obj_dump_attributes(obj)
    print('========================== obj_dump end ==========================')

def obj_dump_attributes(obj, level=1):
    """Print object attributes.

    :param obj:          Object.
    :param level:        How many levels to print.

    :returns: None.
    """
    for a in dir(obj):
        if re.match('__.+__', a):   # Escape all special attributes, like __abstractmethods__, for which val = getattr(obj, a) might fail
            continue
        val = getattr(obj, a)
        if isinstance(val, (int, float, str, list, dict, set, tuple)):
            print(level*' ' + a + '(%s): ' % str(type(val)) + str(val))
        else:
            print(level*' ' + a + ':')
            obj_dump_attributes(val, level=level+1)

def vpp_startup_conf_remove_param(filename, path):
    with FwStartupConf(filename) as conf:
        conf.del_simple_param(path)

def vpp_startup_conf_add_nopci(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        tup = p.create_element('dpdk')
        config.append(tup)
    if p.get_element(config['dpdk'], 'no-pci') == None:
        config['dpdk'].append(p.create_element('no-pci'))
        p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_nopci(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
       return (True, None)
    if p.get_element(config['dpdk'], 'no-pci') == None:
        return (True, None)
    p.remove_element(config['dpdk'], 'no-pci')
    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_add_devices(vpp_config_filename, devices):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        tup = p.create_element('dpdk')
        config.append(tup)

    for dev in devices:
        dev_short = dev_id_to_short(dev)
        dev_full = dev_id_to_full(dev)
        addr_type, addr_short = dev_id_parse(dev_short)
        addr_type, addr_full = dev_id_parse(dev_full)
        if addr_type == "pci":
            old_config_param = 'dev %s' % addr_full
            new_config_param = 'dev %s' % addr_short
            if p.get_element(config['dpdk'],old_config_param) != None:
                p.remove_element(config['dpdk'], old_config_param)
            if p.get_element(config['dpdk'],new_config_param) == None:
                tup = p.create_element(new_config_param)
                config['dpdk'].append(tup)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_devices(vpp_config_filename, devices):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()

    if config['dpdk'] == None:
        return
    for dev in devices:
        dev = dev_id_to_short(dev)
        _, addr = dev_id_parse(dev)
        config_param = 'dev %s' % addr
        key = p.get_element(config['dpdk'],config_param)
        if key:
            p.remove_element(config['dpdk'], key)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def get_lte_interfaces_names():
    names = []
    interfaces = psutil.net_if_addrs()

    for nic_name, _ in list(interfaces.items()):
        dev_id = get_interface_dev_id(nic_name)
        if dev_id and is_lte_interface(nic_name):
            names.append(nic_name)

    return names

def traffic_control_add_del_dev_ingress(dev_name, is_add):
    try:
        subprocess.check_call('sudo tc -force qdisc %s dev %s ingress handle ffff:' % ('add' if is_add else 'delete', dev_name), shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def traffic_control_replace_dev_root(dev_name):
    try:
        subprocess.check_call('sudo tc -force qdisc replace dev %s root handle 1: htb' % dev_name, shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def traffic_control_remove_dev_root(dev_name):
    try:
        subprocess.check_call('sudo tc -force qdisc del dev %s root' % dev_name, shell=True)
        return (True, None)
    except Exception:
        return (True, None)

def reset_traffic_control():
    fwglobals.log.debug('clean Linux traffic control settings')
    search = []
    lte_interfaces = get_lte_interfaces_names()

    if lte_interfaces:
        search.extend(lte_interfaces)

    for term in search:
        try:
            subprocess.check_call('sudo tc -force qdisc del dev %s root 2>/dev/null' % term, shell=True)
        except:
            pass

        try:
            subprocess.check_call('sudo tc -force qdisc del dev %s ingress handle ffff: 2>/dev/null' % term, shell=True)
        except:
            pass

    return True

def remove_linux_bridges():
    try:
        lines = subprocess.check_output('ls -l /sys/class/net/ | grep br_', shell=True).decode().splitlines()
        for line in lines:
            bridge_name = line.rstrip().split('/')[-1]
            try:
                subprocess.check_call("sudo ip link set %s down " % bridge_name, shell=True)
            except:
                pass
            try:
                subprocess.check_call('sudo brctl delbr %s' % bridge_name, shell=True)
            except:
                pass
        return True
    except:
        return True

def reset_dhcpd():
    if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP, fwglobals.g.DHCPD_CONFIG_FILE)

    try:
        subprocess.check_call('sudo systemctl stop isc-dhcp-server', shell=True)
    except:
        return False

    return True

def modify_dhcpd(is_add, params):
    """Modify /etc/dhcp/dhcpd configuration file.

    :param params:   Parameters from flexiManage.

    :returns: String with sed commands.
    """
    dev_id         = params['interface']
    range_start = params.get('range_start', '')
    range_end   = params.get('range_end', '')
    dns         = params.get('dns', {})
    mac_assign  = params.get('mac_assign', {})

    interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
    if not interfaces:
        return (False, "modify_dhcpd: %s was not found" % (dev_id))

    address = IPNetwork(interfaces[0]['addr'])
    router = str(address.ip)
    subnet = str(address.network)
    netmask = str(address.netmask)

    if not os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE, fwglobals.g.DHCPD_CONFIG_FILE_BACKUP)

    config_file = fwglobals.g.DHCPD_CONFIG_FILE

    remove_string = 'sudo sed -e "/subnet %s netmask %s {/,/}/d" ' \
                    '-i %s; ' % (subnet, netmask, config_file)

    range_string = ''
    if range_start:
        range_string = 'range %s %s;\n' % (range_start, range_end)

    if dns:
        dns_string = 'option domain-name-servers'
        for d in dns[:-1]:
            dns_string += ' %s,' % d
        dns_string += ' %s;\n' % dns[-1]
    else:
        dns_string = ''

    subnet_string = 'subnet %s netmask %s' % (subnet, netmask)
    routers_string = 'option routers %s;\n' % (router)
    dhcp_string = 'echo "' + subnet_string + ' {\n' + range_string + \
                 routers_string + dns_string + '}"' + ' | sudo tee -a %s;' % config_file

    if is_add == 1:
        exec_string = remove_string + dhcp_string
    else:
        exec_string = remove_string

    for mac in mac_assign:
        remove_string_2 = 'sudo sed -e "/host %s {/,/}/d" ' \
                          '-i %s; ' % (mac['host'], config_file)

        host_string = 'host %s {\n' % (mac['host'])
        ethernet_string = 'hardware ethernet %s;\n' % (mac['mac'])
        ip_address_string = 'fixed-address %s;\n' % (mac['ipv4'])
        mac_assign_string = 'echo "' + host_string + ethernet_string + ip_address_string + \
                            '}"' + ' | sudo tee -a %s;' % config_file

        if is_add == 1:
            exec_string += remove_string_2 + mac_assign_string
        else:
            exec_string += remove_string_2

    try:
        output = subprocess.check_output(exec_string, shell=True).decode()
    except Exception as e:
        return (False, "Exception: %s" % str(e))

    return True

def vpp_multilink_update_labels(labels, remove, next_hop=None, dev_id=None, sw_if_index=None, result_cache=None):
    """Updates VPP with flexiwan multilink labels.
    These labels are used for Multi-Link feature: user can mark interfaces
    or tunnels with labels and than add policy to choose interface/tunnel by
    label where to forward packets to.

        REMARK: this function is temporary solution as it uses VPP CLI to
    configure lables. Remove it, when correspondent Python API will be added.
    In last case the API should be called directly from translation.

    :param labels:      python list of labels
    :param is_dia:      type of labels (DIA - Direct Internet Access)
    :param remove:      True to remove labels, False to add.
    :param dev_id:      Interface bus address if device to apply labels to.
    :param next_hop:    IP address of next hop.
    :param result_cache: cache, key and variable, that this function should store in the cache:
                            {'result_attr': 'next_hop', 'cache': <dict>, 'key': <key>}

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels, remove)
    ids = ','.join(map(str, ids_list))

    if dev_id:
        vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    elif sw_if_index:
        vpp_if_name = vpp_sw_if_index_to_name(sw_if_index)
    else:
        return (False, "Neither 'dev_id' nor 'sw_if_index' was found in params")

    if not vpp_if_name:
        return (False, "'vpp_if_name' was not found for %s" % dev_id)

    if not next_hop:
        tap = vpp_if_name_to_tap(vpp_if_name)
        next_hop, _ = get_interface_gateway(tap)
    if not next_hop:
        return (False, "'next_hop' was not provided and there is no default gateway")

    op = 'del' if remove else 'add'

    vppctl_cmd = 'fwabf link %s label %s via %s %s' % (op, ids, next_hop, vpp_if_name)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    # Store 'next_hope' in cache if provided by caller.
    #
    if result_cache and result_cache['result_attr'] == 'next_hop':
        key = result_cache['key']
        result_cache['cache'][key] = next_hop

    return (True, None)


def vpp_multilink_update_policy_rule(add, links, policy_id, fallback, order, acl_id=None, priority=None):
    """Updates VPP with flexiwan policy rules.
    In general, policy rules instruct VPP to route packets to specific interface,
    which is marked with multilink label that noted in policy rule.

        REMARK: this function is temporary solution as it uses VPP CLI to
    configure policy rules. Remove it, when correspondent Python API will be added.
    In last case the API should be called directly from translation.

    :param params: params - rule parameters:
                        policy-id - the policy id (two byte integer)
                        labels    - labels of interfaces to be used for packet forwarding
                        remove    - True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    op = 'add' if add else 'del'

    lan_vpp_name_list      = get_interface_vpp_names(type='lan')
    loopback_vpp_name_list = get_tunnel_interface_vpp_names()
    interfaces = lan_vpp_name_list + loopback_vpp_name_list

    if not add:
        for if_vpp_name in interfaces:
            vpp_multilink_attach_policy_rule(if_vpp_name, int(policy_id), priority, 0, True)
        fwglobals.g.policies.remove_policy(policy_id)

    fallback = 'fallback drop' if re.match(fallback, 'drop') else ''
    order    = 'select_group random' if re.match(order, 'load-balancing') else ''

    if acl_id is None:
        vppctl_cmd = 'fwabf policy %s id %d action %s %s' % (op, policy_id, fallback, order)
    else:
        vppctl_cmd = 'fwabf policy %s id %d acl %d action %s %s' % (op, policy_id, acl_id, fallback, order)

    group_id = 1
    for link in links:
        order  = 'random' if re.match(link.get('order', 'None'), 'load-balancing') else ''
        labels = link['pathlabels']
        ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels)
        ids = ','.join(map(str, ids_list))

        vppctl_cmd += ' group %u %s labels %s' % (group_id, order, ids)
        group_id = group_id + 1

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None or re.search('unknown|failed|ret=-', out):
        return (False, "failed vppctl_cmd=%s: %s" % (vppctl_cmd, out))

    if add:
        fwglobals.g.policies.add_policy(policy_id, priority)
        for if_vpp_name in interfaces:
            vpp_multilink_attach_policy_rule(if_vpp_name, int(policy_id), priority, 0, False)

    return (True, None)

def vpp_multilink_attach_policy_rule(int_name, policy_id, priority, is_ipv6, remove):
    """Attach VPP with flexiwan policy rules.

    :param int_name:  The name of the interface in VPP
    :param policy_id: The policy id (two byte integer)
    :param priority:  The priority (integer)
    :param is_ipv6:   True if policy should be applied on IPv6 packets, False otherwise.
    :param remove:    True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    op = 'del' if remove else 'add'
    ip_version = 'ip6' if is_ipv6 else 'ip4'

    vppctl_cmd = 'fwabf attach %s %s policy %d priority %d %s' % (ip_version, op, policy_id, priority, int_name)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None or re.search('unknown|failed|ret=-', out):
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    return (True, None)

def get_interface_vpp_names(type=None):
    res = []
    interfaces = fwglobals.g.router_cfg.get_interfaces()
    for params in interfaces:
        if type == None or re.match(type, params['type'], re.IGNORECASE):
            sw_if_index = dev_id_to_vpp_sw_if_index(params['dev_id'])
            if_vpp_name = vpp_sw_if_index_to_name(sw_if_index)
            res.append(if_vpp_name)
    return res

def get_tunnel_interface_vpp_names():
    res = []
    tunnels = fwglobals.g.router_cfg.get_tunnels()
    for params in tunnels:
        sw_if_index = vpp_ip_to_sw_if_index(params['loopback-iface']['addr'])
        if_vpp_name = vpp_sw_if_index_to_name(sw_if_index)
        res.append(if_vpp_name)
    return res

def add_static_route(addr, via, metric, remove, dev_id=None):
    """Add static route.

    :param addr:            Destination network.
    :param via:             Gateway address.
    :param metric:          Metric.
    :param remove:          True to remove route.
    :param dev_id:          Bus address of device to be used for outgoing packets.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    if addr == 'default':
        return (True, None)

    if not linux_check_gateway_exist(via):
        return (True, None)

    metric = ' metric %s' % metric if metric else ' metric 0'
    op     = 'replace'

    cmd_show = "sudo ip route show exact %s %s" % (addr, metric)
    try:
        output = subprocess.check_output(cmd_show, shell=True).decode()
    except:
        return False

    next_hop = ''
    if output:
        removed = False
        lines   = output.splitlines()
        for line in lines:
            words = line.split('via ')
            if len(words) > 1:
                if remove and not removed and re.search(via, words[1]):
                    removed = True
                    continue

                next_hop += ' nexthop via ' + words[1]

    if remove:
        if not next_hop:
            op = 'del'
        cmd = "sudo ip route %s %s%s %s" % (op, addr, metric, next_hop)
    else:
        if via in next_hop:
            return False
        if not dev_id:
            cmd = "sudo ip route %s %s%s nexthop via %s %s" % (op, addr, metric, via, next_hop)
        else:
            tap = dev_id_to_tap(dev_id)
            if not tap:
                return False
            cmd = "sudo ip route %s %s%s nexthop via %s dev %s %s" % (op, addr, metric, via, tap, next_hop)

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True).decode()
    except Exception as e:
        if op == 'del':
            fwglobals.log.debug("'%s' failed: %s, ignore this error" % (cmd, str(e)))
            return True
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

    return True

def vpp_set_dhcp_detect(dev_id, remove):
    """Enable/disable DHCP detect feature.

    :param params: params:
                        dev_id -  Interface device bus address.
                        remove  - True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    addr_type, _ = dev_id_parse(dev_id)

    if addr_type != "pci":
        return (False, "addr type needs to be a pci address")

    op = 'del' if remove else ''

    sw_if_index = dev_id_to_vpp_sw_if_index(dev_id)
    int_name = vpp_sw_if_index_to_name(sw_if_index)


    vppctl_cmd = 'set dhcp detect intfc %s %s' % (int_name, op)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    return True

def tunnel_change_postprocess(add, addr):
    """Tunnel add/remove postprocessing

    :param params: params - rule parameters:
                        add -  True if tunnel is added, False otherwise.
                        addr - loopback address

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    policies = fwglobals.g.policies.policies_get()
    if len(policies) == 0:
        return

    sw_if_index = vpp_ip_to_sw_if_index(addr)
    if_vpp_name = vpp_sw_if_index_to_name(sw_if_index)
    remove = not add

    for policy_id, priority in list(policies.items()):
        vpp_multilink_attach_policy_rule(if_vpp_name, int(policy_id), priority, 0, remove)


# The messages received from flexiManage are not perfect :)
# Some of them should be not sent at all, some of them include modifications
# that are not importants, some of them do not comply with expected format.
# Below you can find list of problems fixed by this function:
#
# 1. May-2019 - message aggregation is not well defined in protocol between
# device and server. It uses several types of aggregations:
#   1. 'start-router' aggregation: requests are embedded into 'params' field on some request
#   2. 'add-interface' aggregation: 'params' field is list of 'interface params'
#   3. 'list' aggregation: the high level message is a list of requests
# As protocol is not well defined on this matter, for now we assume
# that 'list' is used for FWROUTER_API requests only (add-/remove-/modify-),
# so it should be handled as atomic operation and should be reverted in case of
# failure of one of the requests in opposite order - from the last succeeded
# request to the first, when the whole operation is considered to be failed.
# Convert both type of aggregations into same format:
# {
#   'message': 'aggregated',
#   'params' : {
#                'requests':     <list of aggregated requests>,
#                'original_msg': <original message>
#              }
# }
# The 'original_msg' is needed for configuration hash feature - every received
# message is used for signing router configuration to enable database sync
# between device and server. Once the protocol is fixed, there will be no more
# need in this proprietary format.
#
# 2. Nov-2020 - the 'add-/modify-interface' message might include both 'dhcp': 'yes'
# and 'ip' and 'gw' fields. These IP and GW are not used by the agent, but
# change in their values causes unnecessary removal and adding back interface
# and, as a result of this,  restart of network daemon and reconnection to
# flexiManage. To avoid this we fix the received message by cleaning 'ip' and
# 'gw' fields if 'dhcp' is 'yes'. Than if the fixed message includes no other
# modified parameters, it will be ignored by the agent.
#
def fix_received_message(msg):

    def _fix_aggregation_format(msg):
        requests = []

        # 'list' aggregation
        if type(msg) == list:
            return  \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': copy.deepcopy(msg) }
                }

        # 'start-router' aggregation
        # 'start-router' might include interfaces and routes. Move them into list.
        if msg['message'] == 'start-router' and 'params' in msg:

            start_router_params = copy.deepcopy(msg['params'])  # We are going to modify params, so preserve original message
            if 'interfaces' in start_router_params:
                for iface_params in start_router_params['interfaces']:
                    requests.append(
                        {
                            'message': 'add-interface',
                            'params' : iface_params
                        })
                del start_router_params['interfaces']
            if 'routes' in start_router_params:
                for route_params in start_router_params['routes']:
                    requests.append(
                        {
                            'message': 'add-route',
                            'params' : route_params
                        })
                del start_router_params['routes']

            if len(requests) > 0:
                if bool(start_router_params):  # If there are params after deletions above - use them
                    requests.append(
                        {
                            'message': 'start-router',
                            'params' : start_router_params
                        })
                else:
                    requests.append(
                        {
                            'message': 'start-router'
                        })
                return \
                    {
                        'message': 'aggregated',
                        'params' : { 'requests': requests }
                    }

        # 'add-X' aggregation
        # 'add-interface'/'remove-interface' can have actually a list of interfaces.
        # This is done by setting 'params' as a list of interface params, where
        # every element represents parameters of some interface.
        if re.match('add-|remove-', msg['message']) and type(msg['params']) is list:

            for params in msg['params']:
                requests.append(
                    {
                        'message': msg['message'],
                        'params' : copy.deepcopy(params)
                    })

            return \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': requests }
                }

        # Remove NULL elements from aggregated requests, if sent by bogus flexiManage
        #
        if msg['message'] == 'aggregated':
            requests = [copy.deepcopy(r) for r in msg['params']['requests'] if r]
            return \
                {
                    'message': 'aggregated',
                    'params' : { 'requests': requests }
                }

        # No conversion is needed here.
        # We return copy of object in order to be consistent with previous 'return'-s
        # which return new object. The caller function might rely on this,
        # e.g. see the fwglobals.g.handle_request() assumes
        #
        return copy.deepcopy(msg)


    def _fix_dhcp(msg):

        def _fix_dhcp_params(params):
            if params.get('dhcp') == 'yes':
                params['addr']    = ''
                params['addr6']   = ''
                params['gateway'] = ''

        if re.match('(add|modify)-interface', msg['message']):
            _fix_dhcp_params(msg['params'])
            return msg
        if re.match('aggregated|sync-device', msg['message']):
            for request in msg['params']['requests']:
                if re.match('(add|modify)-interface', request['message']):
                    _fix_dhcp_params(request['params'])
            return msg
        return msg

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # Order of functions is important, as the first one (_fix_aggregation_format())
    # creates clone of the received message, so the rest functions can simply
    # modify it as they wish!
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    msg = _fix_aggregation_format(msg)
    msg = _fix_dhcp(msg)
    return msg


def wifi_get_available_networks(dev_id):
    """Get WIFI available access points.

    :param dev_id: Bus address of interface to get for.

    :returns: string array of essids
    """
    linux_if = dev_id_to_linux_if(dev_id)

    networks = []
    if linux_if:
        def clean(n):
            n = n.replace('"', '')
            n = n.strip()
            n = n.split(':')[-1]
            return n

        # make sure the interface is up
        cmd = 'ip link set dev %s up' % linux_if
        subprocess.check_call(cmd, shell=True)

        try:
            cmd = 'iwlist %s scan | grep ESSID' % linux_if
            networks = subprocess.check_output(cmd, shell=True).decode().splitlines()
            networks = list(map(clean, networks))
            return networks
        except subprocess.CalledProcessError:
            return networks

    return networks

def connect_to_wifi(params):
    interface_name = dev_id_to_linux_if(params['dev_id'])

    if interface_name:
        essid = params['essid']
        password = params['password']

        wpaIsRun = True if pid_of('wpa_supplicant') else False
        if wpaIsRun:
            os.system('sudo killall wpa_supplicant')
            time.sleep(3)

        # create config file
        subprocess.check_call('wpa_passphrase %s %s | sudo tee /etc/wpa_supplicant.conf' % (essid, password), shell=True)

        try:
            subprocess.check_call('wpa_supplicant -i %s -c /etc/wpa_supplicant.conf -D wext -B -C /var/run/wpa_supplicant' % interface_name, shell=True)
            time.sleep(3)

            output = subprocess.check_output('wpa_cli  status | grep wpa_state | cut -d"=" -f2', shell=True).decode().strip()
            if output == 'COMPLETED':
                if params['useDHCP']:
                    subprocess.check_call('dhclient %s' % interface_name, shell=True)
                return True
            else:
                return False
        except subprocess.CalledProcessError:
            return False

    return False

def is_lte_interface_by_dev_id(dev_id):
    if_name = dev_id_to_linux_if(dev_id)
    if not if_name:
        return False
    return is_lte_interface(if_name)

def is_lte_interface(if_name):
    """Check if interface is LTE.

    :param dev_id: Bus address of interface to check.

    :returns: Boolean.
    """
    driver = get_interface_driver(if_name)
    supported_lte_drivers = ['cdc_mbim']
    if driver in supported_lte_drivers:
        return True

    return False

def lte_get_saved_apn():
    cmd = 'cat /etc/mbim-network.conf'
    try:
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        configs = out.split('=')
        if configs[0] == "APN":
            return configs[1]
        return ''
    except subprocess.CalledProcessError:
        return ''

    return ''

def configure_hostapd(dev_id, configuration):
    try:

        for band in configuration:
            config = configuration[band]

            if config['enable'] == False:
                continue

            if_name = dev_id_to_linux_if(dev_id)
            data = {
                'ssid'                 : config.get('ssid', 'fwrouter_ap_%s' % band),
                'interface'            : if_name,
                'macaddr_acl'          : 0,
                'driver'               : 'nl80211',
                'auth_algs'            : 3,
                'ignore_broadcast_ssid': 1 if config.get('hideSsid', 0) == True else 0,
                'eap_server'           : 0,
                'logger_syslog'        : -1,
                'logger_syslog_level'  : 2,
                'logger_stdout'        : -1,
                'logger_stdout_level'  : 2,
                'max_num_sta'          : 128,
                'ctrl_interface'       : '/var/run/hostapd',
                'ctrl_interface_group' : 0,
                'wmm_enabled'          : 1
            }

            if band == '5GHz':
                data['uapsd_advertisement_enabled'] = 1
                data['wmm_ac_bk_cwmin'] = 4
                data['wmm_ac_bk_cwmax'] = 10
                data['wmm_ac_bk_aifs'] = 7
                data['wmm_ac_bk_txop_limit'] = 0
                data['wmm_ac_bk_acm'] = 0
                data['wmm_ac_be_aifs'] = 3
                data['wmm_ac_be_cwmin'] = 4
                data['wmm_ac_be_cwmax'] = 10
                data['wmm_ac_be_txop_limit'] = 0
                data['wmm_ac_be_acm'] = 0
                data['wmm_ac_vi_aifs'] = 2
                data['wmm_ac_vi_cwmin'] = 3
                data['wmm_ac_vi_cwmax'] = 4
                data['wmm_ac_vi_txop_limit'] = 94
                data['wmm_ac_vi_acm'] = 0
                data['wmm_ac_vo_aifs'] = 2
                data['wmm_ac_vo_cwmin'] = 2
                data['wmm_ac_vo_cwmax'] = 3
                data['wmm_ac_vo_txop_limit'] = 47
                data['wmm_ac_vo_acm'] = 0

                data['tx_queue_data3_aifs'] = 7
                data['tx_queue_data3_cwmin'] = 15
                data['tx_queue_data3_cwmax'] = 1023
                data['tx_queue_data3_burst'] = 0
                data['tx_queue_data2_aifs'] = 3
                data['tx_queue_data2_cwmin'] = 15
                data['tx_queue_data2_cwmax'] = 63
                data['tx_queue_data2_burst'] = 0
                data['tx_queue_data1_aifs'] = 1
                data['tx_queue_data1_cwmin'] = 7
                data['tx_queue_data1_cwmax'] = 15
                data['tx_queue_data1_burst'] = 3.0
                data['tx_queue_data0_aifs'] = 1
                data['tx_queue_data0_cwmin'] = 3
                data['tx_queue_data0_cwmax'] = 7
                data['tx_queue_data0_burst'] = 1.5

            # Channel
            channel = config.get('channel', '0')
            data['channel'] = channel

            country_code = config.get('region', 'US')
            data['country_code'] = country_code
            if channel == '0':
                data['ieee80211d'] = 1
            data['ieee80211h'] = 0

            ap_mode = config.get('operationMode', 'g')

            if ap_mode == "g":
                data['hw_mode']       = 'g'

            elif ap_mode == "n":
                if band == '5GHz':
                    data['hw_mode']       = 'a'
                else:
                    data['hw_mode']       = 'g'

                data['ieee80211n']    = 1
                data['ht_capab']      = '[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'

            elif ap_mode == "a":
                data['hw_mode']       = 'a'
                data['ieee80211n']    = 1
                data['ieee80211ac']   = 0
                data['wmm_enabled']   = 0

            elif ap_mode == "ac":
                data['hw_mode']       = 'a'
                data['ieee80211ac']   = 1
                data['ieee80211n']    = 1
                data['ht_capab']      = '[HT40+][LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1][DSSS_CCK-40]'
                data['wmm_enabled']   = 1
                data['vht_oper_chwidth']   = 0
                data['vht_capab']      = '[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]'

            security_mode = config.get('securityMode', 'wpa2-psk')

            if security_mode == "wep":
                data['wep_default_key']       = 1
                data['wep_key1']              = '"%s"' % config.get('password', 'fwrouter_ap')
                data['wep_key_len_broadcast'] = 5
                data['wep_key_len_unicast']   = 5
                data['wep_rekey_period']      = 300
            elif security_mode == "wpa-psk":
                data['wpa'] = 1
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'TKIP CCMP'
            elif security_mode == "wpa2-psk":
                data['wpa'] = 2
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'CCMP'
                data['rsn_pairwise']   = 'CCMP'
                data['wpa_key_mgmt']   = 'WPA-PSK'
            elif security_mode == "wpa-psk/wpa2-psk":
                data['wpa'] = 3
                data['wpa_passphrase'] = config.get('password', 'fwrouter_ap')
                data['wpa_pairwise']   = 'TKIP CCMP'
                data['rsn_pairwise']   = 'CCMP'

            with open(fwglobals.g.HOSTAPD_CONFIG_DIRECTORY + 'hostapd_%s_fwrun.conf' % band, 'w+') as f:
                txt = ''
                for key in data:
                    txt += '%s=%s\n' % (key, data[key])

                file_write_and_flush(f, txt)

        return (True, None)
    except Exception as e:
        return (False, "Exception: %s" % str(e))

def wifi_ap_get_clients(interface_name):
    response = []
    try:
        output = subprocess.check_output('iw dev %s station dump' % interface_name, shell=True).decode()
        if output:
            data = output.splitlines()
            for (idx, line) in enumerate(data):
                if 'Station' in line:
                    mac = line.split(' ')[1]
                    signal =  data[idx + 2].split(':')[-1].strip().replace("'", '') if 'signal' in data[idx + 2] else ''
                    ip = ''

                    try:
                        arp_output = subprocess.check_output('arp -a -n | grep %s' % mac, shell=True).decode()
                    except:
                        arp_output = None

                    if arp_output:
                        ip = arp_output[arp_output.find("(")+1:arp_output.find(")")]

                    entry = {
                        'mac'   : mac,
                        'ip'    : ip,
                        'signal': signal
                    }
                    response.append(entry)
    except Exception:
        pass
    return response

def start_hostapd():
    try:

        if pid_of('hostapd'):
            return (True, None)

        files = glob.glob("%s*fwrun.conf" % fwglobals.g.HOSTAPD_CONFIG_DIRECTORY)
        fwglobals.log.debug("get_hostapd_filenames: %s" % files)

        if files:
            files = ' '.join(files)

            # Start hostapd in background
            subprocess.check_call('sudo hostapd %s -B -t -f %s' % (files, fwglobals.g.HOSTAPD_LOG_FILE), stderr=subprocess.STDOUT, shell=True)
            time.sleep(2)

            pid = pid_of('hostapd')
            if pid:
                return (True, None)

        return (False, 'Error in activating your access point. Your hardware may not support the selected settings')
    except subprocess.CalledProcessError as err:
        stop_hostapd()
        return (False, str(err.output))

def stop_hostapd():
    try:
        if pid_of('hostapd'):
            os.system('killall hostapd')

        files = glob.glob("%s*fwrun.conf" % fwglobals.g.HOSTAPD_CONFIG_DIRECTORY)
        for filePath in files:
            try:
                os.remove(filePath)
            except:
                print("Error while deleting file : ", filePath)
        return (True, None)
    except Exception as e:
        return (False, "Exception: %s" % str(e))

def get_inet6_by_linux_name(inf_name):
    interfaces = psutil.net_if_addrs()
    if inf_name in interfaces:
        for addr in interfaces[inf_name]:
            if addr.family == socket.AF_INET6:
                inet6 = addr.address.split('%')[0]
                if addr.netmask != None:
                    inet6 += "/" + (str(IPAddress(addr.netmask).netmask_bits()))
                return inet6

    return None

def get_lte_interfaces_dev_ids():
    out = {}
    interfaces = psutil.net_if_addrs()
    for nic_name, _ in list(interfaces.items()):
        if is_lte_interface(nic_name):
            dev_id = get_interface_dev_id(nic_name)
            if dev_id:
                out[dev_id] = nic_name
    return out

def configure_lte_interface(params):
    '''
    To get LTE connectivity, two steps are required:
    1. Creating a connection between the modem and cellular provider.
    2. Setting up the Linux interface with the IP/gateway received from the cellular provider
    This function is responsible for the second stage.
    If the vpp is running, we have special logic to configure LTE. This logic handled by the add_interface translator.
    '''
    try:
        dev_id = params['dev_id']
        if vpp_does_run() and is_interface_assigned_to_vpp(dev_id):
            # Make sure interface is up. It might be down due to suddenly disconnected
            nic_name = dev_id_to_linux_if(dev_id)
            os.system('ifconfig %s up' % nic_name)
            return (True, None)

        if not is_lte_interface_by_dev_id(dev_id):
            return (False, "dev_id %s is not a lte interface" % dev_id)

        ip_config = lte_get_ip_configuration(dev_id)
        ip = ip_config['ip']
        gateway = ip_config['gateway']
        metric = params.get('metric', '0')
        if not metric:
            metric = '0'

        nic_name = dev_id_to_linux_if(dev_id)
        os.system('ifconfig %s %s up' % (nic_name, ip))

        # remove old default router
        output = os.popen('ip route list match default | grep %s' % nic_name).read()
        if output:
            routes = output.splitlines()
            for r in routes:
                os.system('ip route del %s' % r)
        # set updated default route
        os.system('route add -net 0.0.0.0 gw %s metric %s' % (gateway, metric))

        # configure dns servers for the interface.
        # If the LTE interface is configured in netplan, the user must set the dns servers manually in netplan.
        set_dns_str = ' '.join(map(lambda server: '--set-dns=' + server, ip_config['dns_servers']))
        if set_dns_str:
            os.system('systemd-resolve %s --interface %s' % (set_dns_str, nic_name))

        clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan
        return (True , None)
    except Exception as e:
        return (False, "Failed to configure lte for dev_id %s. (%s)" % (dev_id, str(e)))

def dev_id_to_usb_device(dev_id):
    try:
        usb_device = get_lte_cache(dev_id, 'usb_device')
        if usb_device:
            return usb_device

        driver = get_interface_driver_by_dev_id(dev_id)
        usb_addr = dev_id.split('/')[-1]
        output = subprocess.check_output('ls /sys/bus/usb/drivers/%s/%s/usbmisc/' % (driver, usb_addr), shell=True).decode().strip()
        set_lte_cache(dev_id, 'usb_device', output)
        return output
    except subprocess.CalledProcessError:
        return None

def _run_qmicli_command(dev_id, flag, print_error=False):
    try:
        device = dev_id_to_usb_device(dev_id) if dev_id else 'cdc-wdm0'
        qmicli_cmd = 'qmicli --device=/dev/%s --device-open-proxy --%s' % (device, flag)
        fwglobals.log.debug("_run_qmicli_command: %s" % qmicli_cmd)
        output = subprocess.check_output(qmicli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_qmicli_command: no output from command (%s)' % qmicli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        if print_error:
            fwglobals.log.debug('_run_qmicli_command: flag: %s. err: %s' % (flag, err.output.strip()))
        return ([], err.output.strip())

def _run_mbimcli_command(dev_id, cmd, print_error=False):
    try:
        device = dev_id_to_usb_device(dev_id) if dev_id else 'cdc-wdm0'
        mbimcli_cmd = 'mbimcli --device=/dev/%s --device-open-proxy %s' % (device, cmd)
        fwglobals.log.debug("_run_mbimcli_command: %s" % mbimcli_cmd)
        output = subprocess.check_output(mbimcli_cmd, shell=True, stderr=subprocess.STDOUT).decode()
        if output:
            return (output.splitlines(), None)
        else:
            fwglobals.log.debug('_run_mbimcli_command: no output from command (%s)' % mbimcli_cmd)
            return ([], None)
    except subprocess.CalledProcessError as err:
        if print_error:
            fwglobals.log.debug('_run_mbimcli_command: cmd: %s. err: %s' % (cmd, err.output.strip()))
        return ([], err.output.strip())

def qmi_get_simcard_status(dev_id):
    return _run_qmicli_command(dev_id, 'uim-get-card-status')

def qmi_get_signals_state(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-signal-strength')

def qmi_get_ip_configuration(dev_id):
    try:
        ip = None
        gateway = None
        primary_dns = None
        secondary_dns = None
        cmd = 'wds-get-current-settings | grep "IPv4 address\\|IPv4 subnet mask\\|IPv4 gateway address\\|IPv4 primary DNS\\|IPv4 secondary DNS"'
        lines, _ = _run_qmicli_command(dev_id, cmd)
        for idx, line in enumerate(lines):
            if 'IPv4 address:' in line:
                ip_without_mask = line.split(':')[-1].strip().replace("'", '')
                mask = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                ip = ip_without_mask + '/' + str(IPAddress(mask).netmask_bits())
                continue
            if 'IPv4 gateway address:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'IPv4 primary DNS:' in line:
                primary_dns = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'IPv4 secondary DNS:' in line:
                secondary_dns = line.split(':')[-1].strip().replace("'", '')
                break
        return (ip, gateway, primary_dns, secondary_dns)
    except Exception:
        return (None, None, None, None)

def qmi_get_operator_name(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-operator-name')

def qmi_get_home_network(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-home-network')

def qmi_get_system_info(dev_id):
    return _run_qmicli_command(dev_id, 'nas-get-system-info')

def qmi_get_packet_service_state(dev_id):
    '''
    The function will return the connection status.
    This is not about existsin session to the modem. But connectivity between modem to the cellular provider
    '''
    return _run_qmicli_command(dev_id, 'wds-get-channel-rates')

def qmi_get_manufacturer(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-manufacturer')

def qmi_get_model(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-model')

def qmi_get_imei(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-ids')

def qmi_get_default_settings(dev_id):
    return _run_qmicli_command(dev_id, 'wds-get-default-settings=3gpp')

def qmi_sim_power_off(dev_id):
    return _run_qmicli_command(dev_id, 'uim-sim-power-off=1')

def qmi_sim_power_on(dev_id):
    return _run_qmicli_command(dev_id, 'uim-sim-power-on=1')

def qmi_get_phone_number(dev_id):
    return _run_qmicli_command(dev_id, 'dms-get-msisdn')

def lte_get_phone_number(dev_id):
    lines, _ = qmi_get_phone_number(dev_id)
    for line in lines:
        if 'MSISDN:' in line:
            return line.split(':')[-1].strip().replace("'", '')
    return ''

def get_at_port(dev_id):
    at_ports = []
    try:
        _, addr = dev_id_parse(dev_id)
        search_dev = '/'.join(addr.split('/')[:-1])
        output = subprocess.check_output('find /sys/bus/usb/devices/%s*/ -name dev' % search_dev, shell=True).decode().splitlines()
        pattern = '(ttyUSB[0-9])'
        tty_devices = []

        if output:
            for line in output:
                match = re.search(pattern, line)
                if match:
                    tty_devices.append(match.group(1))

        if len(tty_devices) > 0:
            for usb_port in tty_devices:
                try:
                    with serial.Serial('/dev/%s' % usb_port, 115200, timeout=1) as ser:
                        ser.write('AT\r')
                        t_end = time.time() + 1
                        while time.time() < t_end:
                            response = ser.readline()
                            if "OK" in response:
                                at_ports.append(ser.name)
                                break
                        ser.close()
                except:
                    pass
        return at_ports
    except:
        return at_ports

def lte_set_modem_to_mbim(dev_id):
    try:
        if_name = dev_id_to_linux_if(dev_id)
        lte_driver = get_interface_driver(if_name)
        if lte_driver == 'cdc_mbim':
            return (True, None)

        hardware_info = lte_get_hardware_info(dev_id)

        vendor = hardware_info['Vendor']
        model =  hardware_info['Model']

        at_commands = []
        if 'Quectel' in vendor or re.match('Quectel', model, re.IGNORECASE): # Special fix for Quectel ec25 mini pci card
            print('Please wait...')
            at_commands = ['AT+QCFG="usbnet",2', 'AT+QPOWD=0']
            at_serial_port = get_at_port(dev_id)
            if at_serial_port and len(at_serial_port) > 0:
                ser = serial.Serial(at_serial_port[0])
                for at in at_commands:
                    ser.write(at + '\r')
                    time.sleep(0.5)
                ser.close()
                time.sleep(10)
                return (True, None)
            return (False, 'AT port not found. dev_id: %s' % dev_id)
        elif 'Sierra Wireless' in vendor:
            print('Please wait...')
            _run_qmicli_command(dev_id, 'dms-swi-set-usb-composition=8')
            _run_qmicli_command(dev_id, 'dms-set-operating-mode=offline')
            _run_qmicli_command(dev_id, 'dms-set-operating-mode=reset')
            time.sleep(10)
            return (True, None)
        else:
            print("Your card is not officially supported. It might work, But you have to switch manually to the MBIM modem")
            return (False, 'vendor or model are not supported. (vendor: %s, model: %s)' % (vendor, model))
    except Exception as e:
        return (False, str(e))


def lte_get_default_settings(dev_id):
    default_settings = get_lte_cache(dev_id, 'default_settings')
    if not default_settings:
        lines, _ = qmi_get_default_settings(dev_id)
        default_settings = {
            'APN'     : '',
            'UserName': '',
            'Password': '',
            'Auth'    : ''
        }
        for line in lines:
            if 'APN' in line:
                default_settings['APN'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'UserName' in line:
                default_settings['UserName'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Password' in line:
                default_settings['Password'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Auth' in line:
                default_settings['Auth'] = line.split(':')[-1].strip().replace("'", '')
                continue

        set_lte_cache(dev_id, 'default_settings', default_settings)
    return default_settings

def lte_get_pin_state(dev_id):
    res = {
        'PIN1_STATUS': '',
        'PIN1_RETRIES': '',
        'PUK1_RETRIES': '',
    }
    lines, _ = qmi_get_simcard_status(dev_id)
    for index, line in enumerate(lines):
        if 'PIN1 state:' in line:
            res['PIN1_STATUS']= line.split(':')[-1].strip().replace("'", '').split(' ')[0]
            res['PIN1_RETRIES']= lines[index + 1].split(':')[-1].strip().replace("'", '').split(' ')[0]
            res['PUK1_RETRIES']= lines[index + 2].split(':')[-1].strip().replace("'", '').split(' ')[0]
            break
    return res

def lte_sim_status(dev_id):
    lines, err = qmi_get_simcard_status(dev_id)
    if err:
        raise Exception(err)

    for line in lines:
        if 'Card state:' in line:
            state = line.split(':')[-1].strip().replace("'", '').split(' ')[0]
            return state
    return ''


def lte_is_sim_inserted(dev_id):
    status = lte_sim_status(dev_id)
    return status == "present"

def get_lte_db_entry(dev_id, key):
    lte_db = fwglobals.g.db.get('lte' ,{})
    dev_id_entry = lte_db.get(dev_id ,{})
    return dev_id_entry.get(key)

def set_lte_db_entry(dev_id, key, value):
    lte_db = fwglobals.g.db.get('lte' ,{})
    dev_id_entry = lte_db.get(dev_id ,{})
    dev_id_entry[key] = value

    lte_db[dev_id] = dev_id_entry
    fwglobals.g.db['lte'] = lte_db # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

def get_lte_cache(dev_id, key):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id, {})
    return lte_interface.get(key)

def set_lte_cache(dev_id, key, value):
    cache = fwglobals.g.cache.lte
    lte_interface = cache.get(dev_id)
    if not lte_interface:
        fwglobals.g.cache.lte[dev_id] = {}
        lte_interface = fwglobals.g.cache.lte[dev_id]
    lte_interface[key] = value

def lte_disconnect(dev_id, hard_reset_service=False):
    try:
        session = get_lte_cache(dev_id, 'session')
        if_name = get_lte_cache(dev_id, 'if_name')
        if not session:
            session = '0' # default session
        if not if_name:
            if_name = dev_id_to_linux_if(dev_id)

        _run_mbimcli_command(dev_id, '--disconnect=%s' % session)
        os.system('sudo ip link set dev %s down && sudo ip addr flush dev %s' % (if_name, if_name))

        # update the cache
        set_lte_cache(dev_id, 'ip', '')
        set_lte_cache(dev_id, 'gateway', '')

        if hard_reset_service:
            _run_qmicli_command(dev_id, 'wds-reset')
            _run_qmicli_command(dev_id, 'nas-reset')
            _run_qmicli_command(dev_id, 'uim-reset')

        clear_linux_interfaces_cache() # remove this code when move ip configuration to netplan

        return (True, None)
    except subprocess.CalledProcessError as e:
        return (False, "Exception: %s" % (str(e)))

def lte_prepare_connection_params(params):
    connection_params = []
    if 'apn' in params and params['apn']:
        connection_params.append('apn=%s' % params['apn'])
    if 'user' in params and params['user']:
        connection_params.append('username=%s' % params['user'])
    if 'password' in params and params['password']:
        connection_params.append('password=%s' % params['password'])
    if 'auth' in params and params['auth']:
        connection_params.append('auth=%s' % params['auth'])

    return ",".join(connection_params)

def qmi_verify_pin(dev_id, pin):
    fwglobals.log.debug('verifying lte pin number')
    lines, err = _run_qmicli_command(dev_id, 'uim-verify-pin=PIN1,%s' % pin)
    time.sleep(2)
    return (lte_get_pin_state(dev_id), err)

def qmi_set_pin_protection(dev_id, pin, is_enable):
    lines, err = _run_qmicli_command(dev_id, 'uim-set-pin-protection=PIN1,%s,%s' % ('enable' if is_enable else 'disable', pin))
    time.sleep(1)
    return (lte_get_pin_state(dev_id), err)

def qmi_change_pin(dev_id, old_pin, new_pin):
    lines, err = _run_qmicli_command(dev_id, 'uim-change-pin=PIN1,%s,%s' % (old_pin, new_pin))
    time.sleep(1)
    return (lte_get_pin_state(dev_id), err)

def qmi_unblocked_pin(dev_id, puk, new_pin):
    _run_qmicli_command(dev_id, 'uim-unblock-pin=PIN1,%s,%s' % (puk, new_pin))
    time.sleep(1)
    return lte_get_pin_state(dev_id)

def mbim_connection_state(dev_id):
    lines, _ = _run_mbimcli_command(dev_id, '--query-connection-state')
    for line in lines:
        if 'Activation state' in line:
            return line.split(':')[-1].strip().replace("'", '')
    return ''

def mbim_is_connected(dev_id):
    return mbim_connection_state(dev_id) == 'activated'

def mbim_registration_state(dev_id):
    res = {
        'register_state': '',
        'network_error' : '',
    }
    lines, _ = _run_mbimcli_command(dev_id, '--query-registration-state --no-open=3 --no-close')
    for line in lines:
        if 'Network error:' in line:
            res['network_error'] = line.split(':')[-1].strip().replace("'", '')
            continue
        if 'Register state:' in line:
            res['register_state'] = line.split(':')[-1].strip().replace("'", '')
            break
    return res

def reset_modem(dev_id):
    set_lte_cache(dev_id, 'state', 'resetting')
    try:
        fwglobals.log.debug('reset_modem: reset starting')

        _run_qmicli_command(dev_id,'dms-set-operating-mode=offline')
        _run_qmicli_command(dev_id,'dms-set-operating-mode=reset')
        time.sleep(10) # reset operation might take few seconds
        _run_qmicli_command(dev_id,'dms-set-operating-mode=online')

        # To reapply set-name for LTE interface we have to call netplan apply here
        netplan_apply("reset_modem")

        fwglobals.log.debug('reset_modem: reset finished')
    except Exception:
        pass

    set_lte_cache(dev_id, 'state', '')
    # clear wrong PIN cache on reset
    set_lte_db_entry(dev_id, 'wrong_pin', None)

def lte_connect(params):
    dev_id = params['dev_id']

    # To avoid wan failover monitor and lte watchdog at this time
    set_lte_cache(dev_id, 'state', 'connecting')

    try:
        # check if sim exists
        if not lte_is_sim_inserted(dev_id):
            qmi_sim_power_off(dev_id)
            time.sleep(1)
            qmi_sim_power_on(dev_id)
            time.sleep(1)
            inserted = lte_is_sim_inserted(dev_id)
            if not inserted:
                raise Exception("Sim is not presented")

        # check PIN status
        pin_state = lte_get_pin_state(dev_id).get('PIN1_STATUS', 'disabled')
        if pin_state not in ['disabled', 'enabled-verified']:
            pin = params.get('pin')
            if not pin:
                raise Exception("PIN is required")

            # If a user enters a wrong pin, the function will fail, but flexiManage will send three times `sync` jobs.
            # As a result, the SIM may be locked. So we save the wrong pin in the cache
            # and we will not try again with this wrong one.
            wrong_pin = get_lte_db_entry(dev_id, 'wrong_pin')
            if wrong_pin and wrong_pin == pin:
                raise Exception("PIN is wrong")

            _, err = qmi_verify_pin(dev_id, pin)
            if err:
                set_lte_db_entry(dev_id, 'wrong_pin', pin)
                raise Exception("PIN is wrong")

        # At this point, we sure that the sim is unblocked.
        # After a block, the sim might open it from different places (manually qmicli command, for example),
        # so we need to make sure to clear this cache
        set_lte_db_entry(dev_id, 'wrong_pin', None)

        # Check if modem already connected to ISP.
        is_modem_connected = mbim_is_connected(dev_id)
        if is_modem_connected:
            set_lte_cache(dev_id, 'state', '')
            return (True, None)

        if_name = dev_id_to_linux_if(dev_id)
        set_lte_cache(dev_id, 'if_name', dev_id_to_linux_if(dev_id))

        # Make sure context is released and set the interface to up
        lte_disconnect(dev_id)
        os.system('ifconfig %s up' % if_name)

        connection_params = lte_prepare_connection_params(params)
        mbim_commands = [
            r'--query-subscriber-ready-status --no-close',
            r'--query-registration-state --no-open=3 --no-close',
            r'--attach-packet-service --no-open=4 --no-close',
            r'--connect=%s --no-open=5 --no-close | grep "Session ID\|IP\|Gateway\|DNS"' % connection_params
        ]
        for cmd in mbim_commands:
            lines, err = _run_mbimcli_command(dev_id, cmd, True)
            if err:
                raise Exception(err)

        for idx, line in enumerate(lines) :
            if 'Session ID:' in line:
                session = line.split(':')[-1].strip().replace("'", '')
                set_lte_cache(dev_id, 'session', session)
                continue
            if 'IP [0]:' in line:
                ip = line.split(':')[-1].strip().replace("'", '')
                set_lte_cache(dev_id, 'ip', ip)
                continue
            if 'Gateway:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                set_lte_cache(dev_id, 'gateway', gateway)
                continue
            if 'DNS [0]:' in line:
                dns_primary = line.split(':')[-1].strip().replace("'", '')
                dns_secondary = lines[idx + 1].split(':')[-1].strip().replace("'", '')
                set_lte_cache(dev_id, 'dns_servers', [dns_primary, dns_secondary])
                break

        set_lte_cache(dev_id, 'state', '')
        return (True, None)
    except Exception as e:
        fwglobals.log.debug('lte_connect: faild to connect lte. %s' % str(e))
        set_lte_cache(dev_id, 'state', '')
        return (False, "Exception: %s" % str(e))

def lte_get_system_info(dev_id):
    result = {
        'Cell_Id'        : '',
        'Operator_Name'  : '',
        'MCC'            : '',
        'MNC'            : ''
    }
    try:
        lines, _ = qmi_get_system_info(dev_id)
        for line in lines:
            if 'Cell ID' in line:
                result['Cell_Id'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'MCC' in line:
                result['MCC'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'MNC' in line:
                result['MNC'] = line.split(':')[-1].strip().replace("'", '')
                continue

        lines, _ = qmi_get_operator_name(dev_id)
        for line in lines:
            if '\tName' in line:
                name = line.split(':', 1)[-1].strip().replace("'", '')
                result['Operator_Name'] = name if bool(re.match("^[a-zA-Z0-9_ :]*$", name)) else ''
                break

    except Exception:
        pass
    return result

def lte_get_hardware_info(dev_id):
    result = {
        'Vendor'   : '',
        'Model'    : '',
        'Imei': '',
    }
    try:
        lines, _ = qmi_get_manufacturer(dev_id)
        for line in lines:
            if 'Manufacturer' in line:
                result['Vendor'] = line.split(':')[-1].strip().replace("'", '')
                break

        lines, _ = qmi_get_model(dev_id)
        for line in lines:
            if 'Model' in line:
                result['Model'] = line.split(':')[-1].strip().replace("'", '')
                break

        lines, _ = qmi_get_imei(dev_id)
        for line in lines:
            if 'IMEI' in line:
                result['Imei'] = line.split(':')[-1].strip().replace("'", '')
                break

    except Exception:
        pass
    return result

def lte_get_packets_state(dev_id):
    result = {
        'Uplink_speed'  : 0,
        'Downlink_speed': 0
    }
    try:
        lines, _ = qmi_get_packet_service_state(dev_id)
        for line in lines:
            if 'Max TX rate' in line:
                result['Uplink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Max RX rate' in line:
                result['Downlink_speed'] = line.split(':')[-1].strip().replace("'", '')
                continue
    except Exception:
        pass
    return result

def lte_get_radio_signals_state(dev_id):
    result = {
        'RSSI' : 0,
        'RSRP' : 0,
        'RSRQ' : 0,
        'SINR' : 0,
        'SNR'  : 0,
        'text' : ''
    }
    try:
        lines, _ = qmi_get_signals_state(dev_id)
        for index, line in enumerate(lines):
            if 'RSSI' in line:
                result['RSSI'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                dbm_num = int(result['RSSI'].split(' ')[0])
                if -95 >= dbm_num:
                    result['text'] = 'Marginal'
                elif -85 >= dbm_num:
                    result['text'] = 'Very low'
                elif -80 >= dbm_num:
                    result['text'] = 'Low'
                elif -70 >= dbm_num:
                    result['text'] = 'Good'
                elif -60 >= dbm_num:
                    result['text'] = 'Very Good'
                elif -50 >= dbm_num:
                    result['text'] = 'Excellent'
                continue
            if 'SINR' in line:
                result['SINR'] = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'RSRQ' in line:
                result['RSRQ'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
            if 'SNR' in line:
                result['SNR'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
            if 'RSRP' in line:
                result['RSRP'] = lines[index + 1].split(':')[-1].strip().replace("'", '')
                continue
    except Exception:
        pass
    return result

def mbim_get_ip_configuration(dev_id):
    ip = None
    gateway = None
    try:
        lines, _ = _run_mbimcli_command(dev_id, '--query-ip-configuration --no-close --no-open=6')
        for line in lines:
            if 'IP [0]:' in line:
                ip = line.split(':')[-1].strip().replace("'", '')
                continue
            if 'Gateway:' in line:
                gateway = line.split(':')[-1].strip().replace("'", '')
                break
        return (ip, gateway)
    except Exception:
        return (ip, gateway)

def lte_get_ip_configuration(dev_id, key=None, cache=True):
    response = {
        'ip'           : '',
        'gateway'      : '',
        'dns_servers'  : []
    }
    try:
        # try to get it from cache
        ip = get_lte_cache(dev_id, 'ip')
        gateway =  get_lte_cache(dev_id, 'gateway')
        dns_servers =  get_lte_cache(dev_id, 'dns_servers')

        # if not exists in cache, take from modem and update cache
        if not ip or not gateway or not dns_servers or cache == False:
            ip, gateway, primary_dns, secondary_dns = qmi_get_ip_configuration(dev_id)

            if ip:
                set_lte_cache(dev_id, 'ip', ip)
            if gateway:
                set_lte_cache(dev_id, 'gateway', gateway)
            if primary_dns and secondary_dns:
                dns_servers = [primary_dns, secondary_dns]
                set_lte_cache(dev_id, 'dns_servers', dns_servers)

        response['ip'] = ip
        response['gateway'] = gateway
        response['dns_servers'] = dns_servers

        if key:
            return response[key]
    except Exception:
        pass
    return response

def is_wifi_interface_by_dev_id(dev_id):
    linux_if = dev_id_to_linux_if(dev_id)
    return is_wifi_interface(linux_if)

def is_wifi_interface(if_name):
    """Check if interface is WIFI.

    :param if_name: Interface name to check.

    :returns: Boolean.
    """
    try:
        lines = subprocess.check_output('iwconfig | grep %s' % if_name, shell=True, stderr=subprocess.STDOUT).decode().splitlines()
        for line in lines:
            if if_name in line and not 'no wireless extensions' in line:
                return True
    except Exception:
        return False

    return False

def get_ethtool_value(linuxif, ethtool_key):
    val = ''
    try:
        cmd = 'ethtool -i %s' % linuxif
        lines = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().splitlines()
        for line in lines:
            if ethtool_key in line:
                val = line.split("%s: " % ethtool_key, 1)[-1]
                break
    except subprocess.CalledProcessError:
        pass

    return val

def get_interface_driver_by_dev_id(dev_id):
    if_name = dev_id_to_linux_if(dev_id)
    return get_interface_driver(if_name)

def get_interface_driver(if_name, cache=True):
    """Get Linux interface driver.

    :param if_name: interface name in Linux.

    :returns: driver name.
    """
    if not if_name:
        fwglobals.log.error('get_interface_driver: if_name is empty')
        return ''

    with fwglobals.g.cache.lock:
        interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)
        if not interface or cache == False:
            fwglobals.g.cache.linux_interfaces_by_name[if_name] = {}
            interface = fwglobals.g.cache.linux_interfaces_by_name.get(if_name)

        driver = interface.get('driver')
        if driver:
            return driver

        driver = get_ethtool_value(if_name, 'driver')

        interface.update({'driver': driver})
        return driver

def is_dpdk_interface(dev_id):
    return not is_non_dpdk_interface(dev_id)

def is_non_dpdk_interface(dev_id):
    """Check if interface is not supported by dpdk.

    :param dev_id: Bus address of interface to check.

    :returns: boolean.
    """

    # 0000:06:00.00 'I210 Gigabit Network Connection' if=eth0 drv=igb unused= 192.168.1.11
    # 0000:0a:00.00 'Ethernet Connection X553 1GbE' if=eth4 drv=ixgbe unused= 10.0.0.1
    # 0000:07:00.00 'I210 Gigabit Network Connection' if=eth2 drv=igb unused=vfio-pci,uio_pci_generic =192.168.0.1

    if is_wifi_interface_by_dev_id(dev_id):
        return True
    if is_lte_interface_by_dev_id(dev_id):
        return True

    return False

def frr_create_ospfd(frr_cfg_file, ospfd_cfg_file, router_id):
    '''Creates the /etc/frr/ospfd.conf file, initializes it with router id and
    ensures that ospf is switched on in the frr configuration'''

    # Ensure that ospfd is switched on in /etc/frr/daemons.
    subprocess.check_call('sudo sed -i -E "s/ospfd=no/ospfd=yes/" %s' % frr_cfg_file, shell=True)

    if os.path.exists(ospfd_cfg_file):
        return

    # Initialize ospfd.conf
    with open(ospfd_cfg_file,"w") as f:
        file_write_and_flush(f,
            'hostname ospfd\n' + \
            'password zebra\n' + \
            'log file /var/log/frr/ospfd.log informational\n' + \
            'log stdout\n' + \
            '!\n' + \
            'router ospf\n' + \
            '    ospf router-id ' + router_id + '\n' + \
            '!\n')

def file_write_and_flush(f, data):
    '''Wrapper over the f.write() method that flushes wrote content
    into the disk immediately

    :param f:       the python file object
    :param data:    the data to write into file
    '''
    f.write(data)
    f.flush()
    os.fsync(f.fileno())

def netplan_apply(caller_name=None):
    '''Wrapper over the f.write() method that flushes wrote content
    into the disk immediately

    :param f:       the python file object
    :param data:    the data to write into file
    '''
    try:
        # Before netplan apply go and note the default route.
        # If it will be changed as a result of netplan apply, we return True.
        #
        if fwglobals.g.fwagent:
            (_, _, dr_dev_id_before, _) = get_default_route()

        # Now go and apply the netplan
        #
        cmd = 'netplan apply'
        log_str = caller_name + ': ' + cmd if caller_name else cmd
        fwglobals.log.debug(log_str)
        os.system(cmd)
        time.sleep(1)  				# Give a second to Linux to configure interfaces

        # Netplan might change interface names, e.g. enp0s3 -> vpp0, or other parameters so reset cache
        #
        fwglobals.g.cache.linux_interfaces_by_name.clear()
        clear_linux_interfaces_cache()

        # IPv6 might be renable if interface name is changed using set-name
        disable_ipv6()

        # Find out if the default route was changed. If it was - reconnect agent.
        #
        if fwglobals.g.fwagent:
            (_, _, dr_dev_id_after, _) = get_default_route()
            if dr_dev_id_before != dr_dev_id_after:
                fwglobals.log.debug(
                    "%s: netplan_apply: default route changed (%s->%s) - reconnect" % \
                    (caller_name, dr_dev_id_before, dr_dev_id_after))
                fwglobals.g.fwagent.reconnect()

    except Exception as e:
        fwglobals.log.debug("%s: netplan_apply failed: %s" % (caller_name, str(e)))
        return False

def compare_request_params(params1, params2):
    """ Compares two dictionaries while normalizing them for comparison
    and ignoring orphan keys that have None or empty string value.
        The orphans keys are keys that present in one dict and don't
    present in the other dict, thanks to Scooter Software Co. for the term :)
        We need this function to pay for bugs in flexiManage code, where
    is provides add-/modify-/remove-X requests for same configuration
    item with inconsistent letter case, None/empty string,
    missing parameters, etc.
        Note! The normalization is done for top level keys only!
    """
    if not params1 or not params2:
        return False
    if type(params1) != type(params2):
        return False
    if type(params1) != dict:
        return (params1 == params2)

    set_keys1   = set(params1.keys())
    set_keys2   = set(params2.keys())
    keys1_only  = list(set_keys1 - set_keys2)
    keys2_only  = list(set_keys2 - set_keys1)
    keys_common = set_keys1.intersection(set_keys2)

    for key in keys1_only:
        if type(params1[key]) == bool or params1[key]:
            # params1 has non-empty string/value that does not present in params2
            return False

    for key in keys2_only:
        if type(params2[key]) == bool or params2[key]:
            # params2 has non-empty string/value that does not present in params1
            return False

    for key in keys_common:
        val1 = params1[key]
        val2 = params2[key]

        # If both values are neither None-s nor empty strings.
        # False booleans will be handled by next 'elif'.
        #
        if val1 and val2:
            if (type(val1) == str) and (type(val2) == str):
                if val1.lower() != val2.lower():
                    return False    # Strings are not equal
            elif type(val1) != type(val2):
                return False        # Types are not equal
            elif val1 != val2:
                return False        # Values are not equal

        # If False booleans or
        # if one of values not exists or empty string
        #
        elif (val1 and not val2) or (not val1 and val2):
            return False

    return True

def check_if_virtual_environment():
    virt_exist = os.popen('dmesg |grep -i hypervisor| grep -i detected').read()
    if virt_exist =='':
        return False
    else:
        return True

def check_root_access():
    if os.geteuid() == 0: return True
    print("Error: requires root privileges, try to run 'sudo'")
    return False

def disable_ipv6():
    """ disable default and all ipv6
    """
    sys_cmd = 'sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Disable IPv6 all command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Disable IPv6 all command successfully executed: %s" % (sys_cmd))

    sys_cmd = 'sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Disable IPv6 default command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Disable IPv6 default command successfully executed: %s" % (sys_cmd))

def set_default_linux_reverse_path_filter(rpf_value):

    """ set default and all (current) rp_filter value of Linux

    : param rpf_value: RPF value to be set using the sysctl command
    """
    sys_cmd = 'sysctl -w net.ipv4.conf.all.rp_filter=%d > /dev/null' % (rpf_value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("RPF set command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("RPF set command successfully executed: %s" % (sys_cmd))

    sys_cmd = 'sysctl -w net.ipv4.conf.default.rp_filter=%d > /dev/null' % (rpf_value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("RPF set command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("RPF set command successfully executed: %s" % (sys_cmd))
    return rc

def set_linux_igmp_max_memberships(value = 4096):
    """ Set limit to allowed simultaneous multicast group membership (linux default is 20)
    """
    sys_cmd = 'sysctl -w net.ipv4.igmp_max_memberships=%d > /dev/null' % (value)
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("Set limit of multicast group membership command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.debug("Set limit of multicast group membership command successfully executed: %s" % (sys_cmd))

def update_linux_metric(prefix, dev, metric):
    """Invokes 'ip route' commands to update metric on the provide device.
    """
    try:
        cmd = "ip route show exact %s dev %s" % (prefix, dev)
        os_route = subprocess.check_output(cmd, shell=True).decode().strip()
        if not os_route:
            raise Exception("'%s' returned nothing" % cmd)
        cmd = "ip route del " + os_route
        ok = not subprocess.call(cmd, shell=True)
        if not ok:
            raise Exception("'%s' failed" % cmd)
        if 'metric ' in os_route:  # Replace metric in os route string
            os_route = re.sub('metric [0-9]+', 'metric %d' % metric, os_route)
        else:
            os_route += ' metric %d' % metric
        cmd = "ip route add " + os_route
        ok = not subprocess.call(cmd, shell=True)
        if not ok:
            raise Exception("'%s' failed" % cmd)
        return (True, None)
    except Exception as e:
        return (False, str(e))

def remove_linux_default_route(dev):
    """Invokes 'ip route del' command to remove default route.
    """
    try:
        cmd = "ip route del default dev %s" % dev
        fwglobals.log.debug(cmd)
        ok = not subprocess.call(cmd, shell=True)
        if not ok:
            raise Exception("'%s' failed" % cmd)
        return True
    except Exception as e:
        fwglobals.log.error(str(e))
        return False

def vmxnet3_unassigned_interfaces_up():
    """This function finds vmxnet3 interfaces that should NOT be controlled by
    VPP and brings them up. We call these interfaces 'unassigned'.
    This hack is needed to prevent disappearing of unassigned interfaces from
    Linux, as VPP captures all down interfaces on start.

    Note for non vmxnet3 interfaces we solve this problem in elegant way - we
    just add assigned interfaces to the white list in the VPP startup.conf,
    so VPP captures only them, while ignoring the unassigned interfaces, either
    down or up. In case of vmxnet3 we can't use the startup.conf white list,
    as placing them there causes VPP to bind them to vfio-pci driver on start,
    so trial to bind them later to the vmxnet3 driver by call to the VPP
    vmxnet3_create() API fails. Hence we go with the dirty workaround of UP state.
    """
    try:
        linux_interfaces = get_linux_interfaces()
        assigned_list    = fwglobals.g.router_cfg.get_interfaces()
        assigned_dev_ids    = [params['dev_id'] for params in assigned_list]

        for dev_id in linux_interfaces:
            if not dev_id in assigned_dev_ids:
                if dev_id_is_vmxnet3(dev_id):
                    os.system("ip link set dev %s up" % linux_interfaces[dev_id]['name'])

    except Exception as e:
        fwglobals.log.debug('vmxnet3_unassigned_interfaces_up: %s (%s)' % (str(e),traceback.format_exc()))
        pass

def get_reconfig_hash():
    """ This function creates a string that holds all the information added to the reconfig
    data, and then create a hash string from it.

    : return : md5 hash result of all the data collected or empty string.
    """
    res = ''

    linux_interfaces = get_linux_interfaces()
    for dev_id in linux_interfaces:
        name = linux_interfaces[dev_id]['name']

        is_lte = is_lte_interface(name)
        if is_lte:
            tap_name = dev_id_to_tap(dev_id, check_vpp_state=True)
            if tap_name:
                name = tap_name

        addr = get_interface_address(name, log=False)
        gw, metric = get_interface_gateway(name)

        addr = addr.split('/')[0] if addr else ''

        res += 'addr:'    + addr + ','
        res += 'gateway:' + gw + ','
        res += 'metric:'  + metric + ','
        if gw and addr:
            res += 'public_ip:'   + linux_interfaces[dev_id]['public_ip'] + ','
            res += 'public_port:' + str(linux_interfaces[dev_id]['public_port']) + ','

    hash = hashlib.md5(res.encode()).hexdigest()
    fwglobals.log.debug("get_reconfig_hash: %s: %s" % (hash, res))
    return hash

def vpp_nat_interface_add(dev_id, remove):

    vpp_if_name = dev_id_to_vpp_if_name(dev_id)
    fwglobals.log.debug("NAT Interface Address - (%s is_delete: %s)" % (vpp_if_name, remove))
    if remove:
        vppctl_cmd = 'nat44 add interface address %s del' % vpp_if_name
    else:
        vppctl_cmd = 'nat44 add interface address %s' % vpp_if_name
    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        fwglobals.log.debug("failed vppctl_cmd=%s" % vppctl_cmd)
        return False


def get_min_metric_device(skip_dev_id):

    metric_min_dev_id = None
    metric_min = sys.maxsize

    wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
    for wan in wan_list:
        if skip_dev_id and skip_dev_id == wan['dev_id']:
            fwglobals.log.trace("Min Metric Check - Skip dev_id: %s" % (skip_dev_id))
            continue

        metric_iter_str = wan.get('metric')
        fwglobals.log.trace("Min Metric Check (Device: %s) Metric: %s" %
            (wan['dev_id'], metric_iter_str))
        metric_iter = int(metric_iter_str or 0)
        metric_iter = get_wan_failover_metric(wan['dev_id'], metric_iter)
        fwglobals.log.trace("Min Metric Check (Device: %s) FO Metric: %d" %
            (wan['dev_id'], metric_iter))
        if metric_iter < metric_min:
            metric_min = metric_iter
            metric_min_dev_id = wan['dev_id']

    return (metric_min_dev_id, metric_min)

def vpp_nat_add_del_identity_mapping(vpp_if_name, protocol, port, is_add):

    del_str = '' if is_add else 'del'
    vppctl_cmd = 'nat44 add identity mapping external %s %s %d vrf 0 %s' %\
        (vpp_if_name, protocol, port, del_str)
    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        fwglobals.log.error("Failed vppctl command: %s" % vppctl_cmd)
    else:
        fwglobals.log.debug("Executed nat44 mapping command: %s" % vppctl_cmd)


def wifi_get_capabilities(dev_id):

    result = {
        'Band 1': {
            # 'Frequencies': [],
            # 'Bitrates': [],
            'Exists': False
        },
        'Band 2': {
            # 'Frequencies': [],
            # 'Capabilities': [],
            # 'Bitrates': [],
            'Exists': False
        }
    }

    def _get_band(output, band_number):
        regex = r'(Band ' + str(band_number) + r':.*?\\n\\t(?!\\t))'
        match = re.search(regex, output,  re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1)

        return ""

    def _parse_key_data(text, output, negative_look_count = 1):
        match = re.search(text, output,  re.MULTILINE | re.IGNORECASE)

        res = list()

        if match:
            result = match.group()
            splitted = result.replace('\\t', '\t').replace('\\n', '\n').splitlines()
            for line in splitted[1:-1]:
                res.append(line.lstrip('\t').strip(' *'))
            return res

        return res

    try:
        output = subprocess.check_output('iw dev', shell=True).decode().splitlines()
        linux_if = dev_id_to_linux_if(dev_id)
        if linux_if in output[1]:
            phy_name = output[0].replace('#', '')
            #output = subprocess.check_output('cat /tmp/jaga', shell=True).replace('\\\\t', '\\t').replace('\\\\n', '\\n').decode()
            # banda1 = _get_band(output2, 1)
            # banda2 = _get_band(output2, 2)

            output = subprocess.check_output('iw %s info' % phy_name, shell=True).decode().replace('\t', '\\t').replace('\n', '\\n')
            result['SupportedModes'] = _parse_key_data('Supported interface modes', output)


            band1 = _get_band(output, 1)
            band2 = _get_band(output, 2)

            if band1:
                result['Band 1']['Exists'] = True
                # result['Band 1']['Frequencies'] = _parse_key_data('Frequencies', band1)
                # result['Band 1']['Bitrates'] = _parse_key_data('Bitrates', band1, 2)
                # result['Band 1']['Capabilities'] = _parse_key_data('Capabilities', band1, 2)

            if band2:
                result['Band 2']['Exists'] = True
                # result['Band 2']['Frequencies'] = _parse_key_data('Frequencies', band2)
                # result['Band 2']['Bitrates'] = _parse_key_data('Bitrates', band2, 2)
                # result['Band 2']['Capabilities'] = _parse_key_data('Capabilities', band2, 2)

        return result
    except Exception:
        return result

def dump(filename=None, path=None, clean_log=False):
    '''This function invokes 'fwdump' utility while ensuring no DoS on disk space.

    :param filename:  the name of the final file where to dump will be tar.gz-ed
    :param clean_log: if True, /var/log/flexiwan/agent.log will be cleaned
    '''
    try:
        cmd = 'fwdump'
        if filename:
            cmd += ' --zip_file ' + filename
        if not path:
            path = fwglobals.g.DUMP_FOLDER
        cmd += ' --dest_folder ' + path

        # Ensure no more than last 5 dumps are saved to avoid disk out of space
        #
        files = glob.glob("%s/*.tar.gz" % path)
        if len(files) > 5:
            files.sort()
            os.remove(files[0])

        subprocess.check_call(cmd + ' > /dev/null 2>&1', shell=True)

        if clean_log:
            os.system("echo '' > %s" % fwglobals.g.ROUTER_LOG_FILE)
    except Exception as e:
        fwglobals.log.error("failed to dump: %s" % (str(e)))

def linux_routes_dictionary_get():
    routes_dict = {}

    # get only our static routes from Linux
    try :
        output = subprocess.check_output('ip route show | grep -v proto', shell=True).decode().strip()
    except:
        return routes_dict

    addr = ''
    metric = 0
    nexthops = set()
    routes = output.splitlines()

    for route in routes:
        part = route.split(' ')[0]
        if re.search('nexthop', part):
            parts = route.split('via ')
            via = parts[1].split(' ')[0]
            nexthops.add(via)
            continue
        else:
            # save multipath route if needed
            if nexthops:
                if metric not in routes_dict:
                    routes_dict[metric] = {addr: copy.copy(nexthops)}
                else:
                    routes_dict[metric][addr] = copy.copy(nexthops)

            # continue with current route
            nexthops.clear()
            metric = 0
            addr = part

        if 'metric' in route:
            parts = route.split('metric ')
            metric = int(parts[1])

        parts = route.split('via ')
        if isinstance(parts, list) and len(parts) > 1:
            via = parts[1].split(' ')[0]
            nexthops.add(via)

        if not nexthops:
            continue

        if metric not in routes_dict:
            routes_dict[metric] = {addr: copy.copy(nexthops)}
        else:
            routes_dict[metric][addr] = copy.copy(nexthops)

        nexthops.clear()
        metric = 0

    return routes_dict

def linux_check_gateway_exist(gw):
    interfaces = psutil.net_if_addrs()
    for if_name in interfaces:
        addresses = interfaces[if_name]
        for address in addresses:
            if address.family == socket.AF_INET:
                network = IPNetwork(address.address + '/' + address.netmask)
                if is_ip_in_subnet(gw, str(network)):
                    return True

    return False

def linux_routes_dictionary_exist(routes, addr, metric, via):
    metric = int(metric)
    if metric in list(routes.keys()):
        if addr in list(routes[metric].keys()):
            if via in routes[metric][addr]:
                return True
    return False

def check_reinstall_static_routes():
    routes_db = fwglobals.g.router_cfg.get_routes()
    routes_linux = linux_routes_dictionary_get()

    for route in routes_db:
        addr = route['addr']
        via = route['via']
        metric = str(route.get('metric', '0'))
        dev = route.get('dev_id', None)

        if linux_routes_dictionary_exist(routes_linux, addr, metric, via):
            continue

        add_static_route(addr, via, metric, False, dev)

def exec_with_timeout(cmd, timeout=60):
    """Run bash command with timeout option

    :param cmd:         Bash command
    :param timeout:     kill process after timeout, default=60sec

    :returns: Command execution result
    """
    state = {'proc':None, 'output':'', 'error':'', 'returncode':0}
    try:
        state['proc'] = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        (state['output'], state['error']) = state['proc'].communicate(timeout=timeout)
    except OSError as err:
        state['error'] = str(err)
        fwglobals.log.error("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    except Exception as err:
        state['error'] = "Error executing command '%s', error: %s" % (str(cmd), str(err))
        fwglobals.log.error("Error executing command '%s', error: %s" % (str(cmd), str(err)))
    state['returncode'] = state['proc'].returncode

    return {'output':state['output'], 'error':state['error'], 'returncode':state['returncode']}

def get_template_data_by_hw(template_fname):
    system_info = subprocess.check_output('lshw -c system', shell=True).decode().strip()
    match = re.findall('(?<=vendor: ).*?\\n|(?<=product: ).*?\\n', system_info)
    if len(match) > 0:
        product = match[0].strip()
        vendor = match[1].strip()
        vendor_product = '%s__%s' % (vendor, product.replace(" ", "_"))

    with open(template_fname, 'r') as stream:
        info = yaml.load(stream, Loader=yaml.BaseLoader)
        shared = info['devices']['globals']
        # firstly, we will try to search for specific variables for the vendor and specific model
        # if it does not exist, we will try to get variables for the vendor
        vendor_product = '%s__%s' % (vendor, product.replace(" ", "_"))
        if vendor_product and vendor_product in info['devices']:
            data = info['devices'][vendor_product]
        elif vendor and vendor in info['devices']:
            data = info['devices'][vendor]
        elif product and product in info['devices']:
            data = info['devices'][product]
        else:
            data = shared

        # loop on global fields and override them with specific device values
        for k, v in shared.items():
            if k in data:
                v.update(data[k])
        data.update(shared)

        return data

def replace_file_variables(template_fname, replace_fname):
    """Replace variables in the json file with the data from the template file.

    For example, assuming we are in Virtualbox, the data from the template file looks:
        VirtualBox:
            __INTERFACE_1__:
            dev_id:       pci:0000:00:08.0
            name:         enp0s8
            __INTERFACE_2__:
            dev_id:       pci:0000:00:09.0
            name:         enp0s9
            __INTERFACE_3__:
            dev_id:       pci:0000:00:03.0
            name:         enp0s3

    The file to replace looks:
        [
            {
                "entity": "agent",
                "message": "start-router",
                "params": {
                    "interfaces": [
                        "__INTERFACE_1__",
                        {
                            "dev_id":"__INTERFACE_2__dev_id",
                            "addr":"__INTERFACE_2__addr",
                            "gateway": "192.168.56.1",
                            "type":"wan",
                            "routing":"ospf"
                        }
                    ]
                }
            }
        ]
    
    The function loops on the requests and replaces the variables.
    There are two types of variables. template and specific field.
    If we want to use all the data for a given interface (addr, gateway, dev_id etc.), we can use __INTERFACE_1__ only.
    If we want to get specifc value from a given interface, we can use __INTERFACE_1__{field_name} (__INTERFACE_1__addr)
    In the example above, we use template variable for interface 1, and specific interfaces values for interface 2.

    :param template_fname:    Path to template file
    :param replace_fname:     Path to json file to replace

    :returns: replaced json file
    """
    data = get_template_data_by_hw(template_fname)
    def replace(input):
        if type(input) == list:
            for idx, value in enumerate(input):
                input[idx] = replace(value)

        elif type(input) == dict:
            for key in input:
                value = input[key]
                input[key] = replace(value)

        elif type(input) == str:
            match = re.search('(__.*__)(.*)', str(input))
            if match:
                interface, field = match.groups()
                if field:
                    new_input = re.sub('__.*__.*', data[interface][field], input)
                    return new_input

                # replace with the template, but remove unused keys, They break the expected JSON files
                template = copy.deepcopy(data[interface])
                del template['addr_no_mask']
                if 'name' in template:
                    del template['name']
                return template
        return input

    # loop on the requests and replace the variables
    with open(replace_fname, 'r') as f:
        requests = json.loads(f.read())

        # cli requests
        if type(requests) == list:
            for req in requests:
                if not 'params' in req:
                    continue
                req['params'] = replace(req['params'])

        # json expected files
        elif type(requests) == dict:
            for req in requests:
                requests[req] = replace(requests[req])

    return requests

def reload_lte_drivers():
    modules = [
        'cdc_mbim',
        'qmi_wwan',
        'option',
        'cdc_wdm',
        'cdc_ncm',
        'usbnet',
        'qcserial',
        'usb_wwan',
        'mii',
        'usbserial'
    ]

    for module in modules:
        os.system('rmmod %s 2>/dev/null' % module)

    for module in modules:
        os.system('modprobe %s' % module)

    time.sleep(2)

    netplan_apply("reload_lte_drivers")

def send_udp_packet(src_ip, src_port, dst_ip, dst_port, dev_name, msg):
    """
    This function sends a UDP packet with provided source/destination parameters and payload.
    : param src_ip     : packet source IP
    : param src_port   : packet source port
    : param dst_ip     : packet destination IP
    : param dst_port   : packet destination port
    : param dev_name   : device name to bind() to
    : param msg        : packet payload

    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        if dev_name != None:
            s.setsockopt(socket.SOL_SOCKET, 25, dev_name.encode())
        s.bind((src_ip, src_port))
    except Exception as e:
        fwglobals.log.error("send_udp_packet: bind: %s" % str(e))
        s.close()
        return

    data = binascii.a2b_hex(msg)
    #fwglobals.log.debug("Packet: sendto: (%s,%d) data %s" %(dst_ip, dst_port, data))
    try:
        s.sendto(data, (dst_ip, dst_port))
    except Exception as e:
        fwglobals.log.error("send_udp_packet: sendto(%s:%d) failed: %s" % (dst_ip, dst_port, str(e)))
        s.close()
        return

    s.close()

def build_timestamped_filename(filename, ext=''):
    '''Incorporates date and time into the filename in format "%Y%M%d_%H%M%S".
    Example:
        build_timestamped_filename("fwdump_EdgeDevice01_", ext='.tar.gz')
        ->
        fwdump_EdgeDevice01_20210510_131900.tar.gz
    '''
    return filename + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ext