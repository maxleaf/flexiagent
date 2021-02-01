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
import re
import fwglobals
import fwnetplan
import fwstats
import shutil
import sys
import traceback
import yaml
from netaddr import IPNetwork, IPAddress

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools' , 'common')
sys.path.append(common_tools)
from fw_vpp_startupconf import FwStartupConf

from fwapplications import FwApps
from fwrouter_cfg   import FwRouterCfg
from fwmultilink    import FwMultilink
from fwpolicies     import FwPolicies
from fwwan_monitor  import get_wan_failover_metric


dpdk = __import__('dpdk-devbind')

def get_device_logs(file, num_of_lines):
    """Get device logs.

    :param file:            File name.
    :param num_of_lines:    Number of lines.

    :returns: Return list.
    """
    try:
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
        subprocess.check_output(cmd, shell=True)
        cmd = 'sudo vppctl show vmxnet3'
        shif_vmxnet3 = subprocess.check_output(cmd, shell=True)
        if shif_vmxnet3 is '':
            cmd = 'sudo vppctl trace add dpdk-input {}'.format(num_of_packets)
        else:
            cmd = 'sudo vppctl trace add vmxnet3-input {}'.format(num_of_packets)
        subprocess.check_output(cmd, shell=True)
        time.sleep(timeout)
        cmd = 'sudo vppctl show trace max {}'.format(num_of_packets)
        res = subprocess.check_output(cmd, shell=True).decode().splitlines()
        # skip first line (contains unnecessary information header)
        return res[1:] if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_device_versions(fname):
    """Get agent version.

    :param fname:           Versions file name.

    :returns: Version value.
    """
    try:
        with open(fname, 'r') as stream:
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

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', 'vpp']).decode()
    except:
        pid = None
    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    runs = True if vpp_pid() else False
    return runs

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

def get_default_route():
    """Get default route.

    :returns: tuple (<IP of GW>, <name of network interface>, <PCI of network interface>).
    """
    (via, dev, metric) = ("", "", 0xffffffff)
    try:
        output = os.popen('ip route list match default').read().decode()
        if output:
            routes = output.splitlines()
            for r in routes:
                _dev = ''   if not 'dev '    in r else r.split('dev ')[1].split(' ')[0]
                _via = ''   if not 'via '    in r else r.split('via ')[1].split(' ')[0]
                _metric = 0 if not 'metric ' in r else int(r.split('metric ')[1].split(' ')[0])
                if _metric < metric:  # The default route among default routes is the one with the lowest metric :)
                    dev    = _dev
                    via    = _via
                    metric = _metric
    except:
        return ("", "", "")

    (pci, _) = get_interface_pci(dev)
    return (via, dev, pci)

def get_interface_gateway(if_name, if_pci=None):
    """Get gateway.

    :param if_name:  name of the interface, gateway for which is returned
    :param if_pci:   PCI of the interface, gateway for which is returned.
                     If provided, the 'if_name' is ignored. The name is fetched
                     from system by PCI.

    :returns: Gateway ip address.
    """
    if if_pci:
        if_name = pci_to_tap(if_pci)

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


def get_binary_interface_gateway_by_pci(pci):
    gw_ip, _ = get_interface_gateway('', if_pci=pci)
    return ipaddress.ip_address(unicode(gw_ip))


def get_all_interfaces():
    """ Get all interfaces from linux. For PCI with address family of AF_INET,
        also store gateway, if exists.
        : return : Dictionary of PCI->IP,GW
    """
    pci_ip_gw = {}
    interfaces = psutil.net_if_addrs()
    for nicname, addrs in interfaces.items():
        pci, _ = get_interface_pci(nicname)
        if not pci:
            continue
        pci_ip_gw[pci] = {}
        pci_ip_gw[pci]['addr'] = ''
        pci_ip_gw[pci]['gw']   = ''
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address.split('%')[0]
                pci_ip_gw[pci]['addr'] = ip
                gateway, _ = get_interface_gateway(nicname)
                pci_ip_gw[pci]['gw'] = gateway if gateway else ''
                break

    return pci_ip_gw

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

def pci_to_full(pci_addr):
    """Convert short PCI into full representation.

    :param pci_addr:      Short PCI address.

    :returns: Full PCI address.
    """
    pc = pci_addr.split('.')
    if len(pc) == 2:
        return pc[0]+'.'+"%02x"%(int(pc[1],16))
    return pci_addr

# Convert 0000:00:08.01 provided by management to 0000:00:08.1 used by Linux
def pci_to_short(pci):
    """Convert full PCI into short representation.

    :param pci_addr:      Full PCI address.

    :returns: Short PCI address.
    """
    l = pci.split('.')
    if len(l[1]) == 2 and l[1][0] == '0':
        pci = l[0] + '.' + l[1][1]
    return pci

def get_linux_interfaces(cached=True):
    """Fetch interfaces from Linux.

    :param cached: if True the data will be fetched from cache.

    :return: Dictionary of interfaces by full form PCI.
    """
    interfaces = {} if not cached else fwglobals.g.cache.pcis
    if cached and interfaces:
        return interfaces

    for (if_name, addrs) in psutil.net_if_addrs().items():
        pci, driver = get_interface_pci(if_name)
        if not pci:
            continue

        interface = {
            'name':             if_name,
            'pciaddr':          pci,
            'driver':           driver,
            'MAC':              '',
            'IPv4':             '',
            'IPv4Mask':         '',
            'IPv6':             '',
            'IPv6Mask':         '',
            'dhcp':             '',
            'gateway':          '',
            'metric':           '',
            'internetAccess':   '',
        }

        for addr in addrs:
            addr_af_name            = af_to_name(addr.family)
            interface[addr_af_name] = addr.address.split('%')[0]
            if addr.netmask != None:
                interface[addr_af_name + 'Mask'] = (str(IPAddress(addr.netmask).netmask_bits()))

        # Add information specific for WAN interfaces
        #
        interface['dhcp'] = fwnetplan.get_dhcp_netplan_interface(if_name)
        interface['gateway'], interface['metric'] = get_interface_gateway(if_name)
        if interface['gateway']:

            # Fetch public address info from STUN module
            #
            _, interface['public_ip'], interface['public_port'], interface['nat_type'] = \
                fwglobals.g.stun_wrapper.find_addr(pci)

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

        interfaces[pci] = interface

    return interfaces

def get_interface_pci(linuxif):
    """Convert Linux interface name into PCI address.

    :param linuxif:      Linux interface name.

    :returns: tuple (PCI address , driver name).
    """
    NETWORK_BASE_CLASS = "02"
    vpp_run = vpp_does_run()
    lines = subprocess.check_output(["lspci", "-Dvmmn"]).decode().splitlines()
    for line in lines:
        vals = line.split("\t", 1)
        if len(vals) == 2:
            # keep slot number
            if vals[0] == 'Slot:':
                slot = vals[1]
            if vals[0] == 'Class:':
                if vals[1][0:2] == NETWORK_BASE_CLASS:
                    interface = pci_to_linux_iface(slot)
                    if not interface and vpp_run:
                        interface = pci_to_tap(slot)
                    if not interface:
                        continue
                    if interface == linuxif:
                        driver = os.path.realpath('/sys/bus/pci/devices/%s/driver' % slot).split('/')[-1]
                        return (pci_to_full(slot), "" if driver=='driver' else driver)
    return ("","")

def pci_to_linux_iface(pci):
    """Convert PCI address into Linux interface name.

    :param pci:      PCI address.

    :returns: Linux interface name.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/class/net/
    # total 0
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s8 -> ../../devices/pci0000:00/0000:00:08.0/net/enp0s8
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s9 -> ../../devices/pci0000:00/0000:00:09.0/net/enp0s9
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 lo -> ../../devices/virtual/net/lo

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    pci = pci_to_short(pci)

    try:
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + pci, shell=True).decode()
    except:
        return None
    if output is None:
        return None
    return output.rstrip().split('/')[-1]

def pci_is_vmxnet3(pci):
    """Check if PCI address is vmxnet3.

    :param pci:      PCI address.

    :returns: 'True' if it is vmxnet3, 'False' otherwise.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/bus/pci/devices/*/driver
    # lrwxrwxrwx 1 root root 0 Jul 17 22:08 /sys/bus/pci/devices/0000:03:00.0/driver -> ../../../../bus/pci/drivers/vmxnet3
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:0b:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:13:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    pci = pci_to_short(pci)

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
        #output = subprocess.check_output("sudo ls -l /sys/bus/pci/devices/%s/driver | grep vmxnet3" % pci, shell=True)
        output = subprocess.check_output("sudo dpdk-devbind -s | grep -E '%s .*vmxnet3'" % pci, shell=True)
    except:
        return False
    if output is None:
        return False
    return True

# 'pci_to_vpp_if_name' function maps interface referenced by pci, eg. '0000:00:08.00'
# into name of interface in VPP, eg. 'GigabitEthernet0/8/0'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def pci_to_vpp_if_name(pci):
    """Convert PCI address into VPP interface name.

    :param pci:      PCI address.

    :returns: VPP interface name.
    """
    pci = pci_to_full(pci)
    vpp_if_name = fwglobals.g.cache.pci_to_vpp_if_name.get(pci)
    if vpp_if_name: return vpp_if_name
    else: return _build_pci_to_vpp_if_name_maps(pci, None)

# 'vpp_if_name_to_pci' function maps interface name, eg. 'GigabitEthernet0/8/0'
# into the pci of that interface, eg. '0000:00:08.00'.
# We use the interface cache mapping, if doesn't exist we rebuild the cache
def vpp_if_name_to_pci(vpp_if_name):
    """Convert PCI address into VPP interface name.

    :param vpp_if_name:      VPP interface name.

    :returns: PCI address.
    """
    pci = fwglobals.g.cache.vpp_if_name_to_pci.get(vpp_if_name)
    if pci: return pci
    else: return _build_pci_to_vpp_if_name_maps(None, vpp_if_name)

# '_build_pci_to_vpp_if_name_maps' function build the local caches of
# pci to vpp_if_name and vise vera
# if pci provided, return the name found for this pci,
# else, if name provided, return the pci for this name,
# else, return None
# To do that we dump all hardware interfaces, split the dump into list by empty line,
# and search list for interface that includes the pci name.
# The dumps brings following table:
#              Name                Idx    Link  Hardware
# GigabitEthernet0/8/0               1    down  GigabitEthernet0/8/0
#   Link speed: unknown
#   ...
#   pci: device 8086:100e subsystem 8086:001e address 0000:00:08.00 numa 0
#
def _build_pci_to_vpp_if_name_maps(pci, vpp_if_name):
    shif = _vppctl_read('show hardware-interfaces')
    if shif == None:
        fwglobals.log.debug("_build_pci_to_vpp_if_name_maps: Error reading interface info")
    data = shif.splitlines()
    for intf in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
            valregex=r"^(\w[^\s]+)\s+\d+\s+(\w+)",
            keyregex=r"\s+pci:.*\saddress\s(.*?)\s")
        if k and v:
            fwglobals.g.cache.pci_to_vpp_if_name[pci_to_full(k)] = v
            fwglobals.g.cache.vpp_if_name_to_pci[v] = pci_to_full(k)

    vmxnet3hw = fwglobals.g.router_api.vpp_api.vpp.api.vmxnet3_dump()
    for hw_if in vmxnet3hw:
        vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
        pci_addr = pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.cache.pci_to_vpp_if_name[pci_addr] = vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_pci[vpp_if_name] = pci_addr

    if pci:
        vpp_if_name = fwglobals.g.cache.pci_to_vpp_if_name.get(pci)
        if vpp_if_name: return vpp_if_name
    elif vpp_if_name:
        pci = fwglobals.g.cache.vpp_if_name_to_pci.get(vpp_if_name)
        if pci: return pci

    fwglobals.log.debug("_build_pci_to_vpp_if_name_maps(%s, %s) not found: sh hard: %s" % (pci, vpp_if_name, shif))
    fwglobals.log.debug("_build_pci_to_vpp_if_name_maps(%s, %s): not found sh vmxnet3: %s" % (pci, vpp_if_name, vmxnet3hw))
    fwglobals.log.debug(str(traceback.extract_stack()))
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

# 'pci_to_vpp_sw_if_index' function maps interface referenced by pci, e.g '0000:00:08.00'
# into index of this interface in VPP, eg. 1.
# To do that we convert firstly the pci into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0', than we dump all VPP interfaces and search for interface
# with this name. If found - return interface index.

def pci_to_vpp_sw_if_index(pci):
    """Convert PCI address into VPP sw_if_index.

    :param pci:      PCI address.

    :returns: sw_if_index.
    """
    vpp_if_name = pci_to_vpp_if_name(pci)
    fwglobals.log.debug("pci_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (pci, str(vpp_if_name)))
    if vpp_if_name is None:
        return None

    sw_ifs = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump()
    for sw_if in sw_ifs:
        if re.match(vpp_if_name, sw_if.interface_name):    # Use regex, as sw_if.interface_name might include trailing whitespaces
            return sw_if.sw_if_index
    fwglobals.log.debug("pci_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (pci, yaml.dump(sw_ifs, canonical=True)))
    return None

# 'pci_to_tap' function maps interface referenced by pci, e.g '0000:00:08.00'
# into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp1.
# To do that we convert firstly the pci into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0' and than we grep output of 'vppctl sh tap-inject'
# command by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def pci_to_tap(pci):
    """Convert PCI address into TAP name.

    :param pci:      PCI address.

    :returns: Linux TAP interface name.
    """
    pci_full = pci_to_full(pci)
    cache    = fwglobals.g.cache.pci_to_vpp_tap_name

    tap = cache.get(pci_full)
    if tap:
        return tap

    vpp_if_name = pci_to_vpp_if_name(pci)
    if vpp_if_name is None:
        return None
    tap = vpp_if_name_to_tap(vpp_if_name)
    if tap:
        cache[pci_full] = tap
    return tap

# 'vpp_if_name_to_tap' function maps name of interface in VPP, e.g. loop0,
# into name of correspondent tap interface in Linux.
# To do that it greps output of 'vppctl sh tap-inject' by the interface name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
#       loop0 -> vpp2
def vpp_if_name_to_tap(vpp_if_name):
    """Convert VPP interface name into Linux TAP interface name.

     :param vpp_if_name:      PCI address.

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
            fwglobals.log.debug("vppctl " + cmd)
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
    for d,v in dpdk.devices.items():
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

def reset_router_config():
    """Reset router config by cleaning DB and removing config files.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        router_cfg.clean()
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

    reset_dhcpd()

def print_router_config(basic=True, full=False, multilink=False, signature=False):
    """Print router configuration.

     :returns: None.
     """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        if basic:
            cfg = router_cfg.dumps(full=full, escape=['add-application','add-multilink-policy'])
        elif multilink:
            cfg = router_cfg.dumps(full=full, types=['add-application','add-multilink-policy'])
        elif signature:
            cfg = router_cfg.get_signature()
        else:
            cfg = ''
        print(cfg)

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
    if r!=None: rx_pkts = r.group(1)
    else: rx_pkts = 0
    # tx packets
    r = re.search(r" tx packets\s+(\d+)?",s)
    if r!=None: tx_pkts = r.group(1)
    else: tx_pkts = 0
    # rx bytes
    r = re.search(r" rx bytes\s+(\d+)?",s)
    if r!=None: rx_bytes = r.group(1)
    else: rx_bytes = 0
    # tx bytes
    r = re.search(r" tx bytes\s+(\d+)?",s)
    if r!=None: tx_bytes = r.group(1)
    else: tx_bytes = 0
    # Add data to res
    res[if_name] = {'rx_pkts':long(rx_pkts), 'tx_pkts':long(tx_pkts), 'rx_bytes':long(rx_bytes), 'tx_bytes':long(tx_bytes)}

def get_vpp_if_count():
    """Get number of VPP interfaces.

     :returns: Dictionary with results.
     """
    shif = _vppctl_read('sh int', wait=False)
    if shif == None:  # Exit with an error
        return {'message':'Error reading interface info', 'ok':0}
    data = shif.splitlines()
    res = {}
    for intf in _get_group_delimiter(data, r"^\w.*?\s"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        _parse_add_if(ifdata, res)
    return {'message':res, 'ok':1}

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
    return mac_str.replace(':', '').encode()

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

def is_str(p):
    """Check if it is a string.

     :param p:          String.

     :returns: 'True' if string and 'False' otherwise.
     """
    if is_python2():
        return type(p)==str or type(p)==unicode
    else:
        return type(p)==str

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
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
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
        if isinstance(val, (int, float, str, unicode, list, dict, set, tuple)):
            print(level*' ' + a + '(%s): ' % str(type(val)) + str(val))
        else:
            print(level*' ' + a + ':')
            obj_dump_attributes(val, level=level+1)

def vpp_startup_conf_add_devices(vpp_config_filename, devices):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)

    if config['dpdk'] == None:
        tup = p.create_element('dpdk')
        config.append(tup)
    for dev in devices:
        dev_short = pci_to_short(dev)
        dev_full = pci_to_full(dev)
        old_config_param = 'dev %s' % dev_full
        new_config_param = 'dev %s' % dev_short
        if p.get_element(config['dpdk'],old_config_param) != None:
            p.remove_element(config['dpdk'], old_config_param)
        if p.get_element(config['dpdk'],new_config_param) == None:
            tup = p.create_element(new_config_param)
            config['dpdk'].append(tup)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_devices(vpp_config_filename, devices):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)

    if config['dpdk'] == None:
        return
    for dev in devices:
        dev_short = pci_to_short(dev)
        config_param = 'dev %s' % dev_short
        key = p.get_element(config['dpdk'],config_param)
        if key:
            p.remove_element(config['dpdk'], key)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def reset_dhcpd():
    if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP, fwglobals.g.DHCPD_CONFIG_FILE)

    cmd = 'sudo systemctl stop isc-dhcp-server'

    try:
        subprocess.check_output(cmd, shell=True)
    except:
        return False

    return True

def modify_dhcpd(is_add, params):
    """Modify /etc/dhcp/dhcpd configuration file.

    :param params:   Parameters from flexiManage.

    :returns: String with sed commands.
    """
    pci         = params['interface']
    range_start = params.get('range_start', '')
    range_end   = params.get('range_end', '')
    dns         = params.get('dns', {})
    mac_assign  = params.get('mac_assign', {})

    interfaces = fwglobals.g.router_cfg.get_interfaces(pci=pci)
    if not interfaces:
        return (False, "modify_dhcpd: %s was not found" % (pci))

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
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

    return True

def vpp_multilink_update_labels(labels, remove, next_hop=None, pci=None, sw_if_index=None, result_cache=None):
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
    :param pci:         PCI if device to apply labels to.
    :param next_hop:    IP address of next hop.
    :param result_cache: cache, key and variable, that this function should store in the cache:
                            {'result_attr': 'next_hop', 'cache': <dict>, 'key': <key>}

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels, remove)
    ids = ','.join(map(str, ids_list))

    if pci:
        vpp_if_name = pci_to_vpp_if_name(pci)
    elif sw_if_index:
        vpp_if_name = vpp_sw_if_index_to_name(sw_if_index)
    else:
        return (False, "Neither 'pci' nor 'sw_if_index' was found in params")

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
            sw_if_index = pci_to_vpp_sw_if_index(params['pci'])
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

    return ipaddress.ip_address(gw_ip)
def add_static_route(addr, via, metric, remove, pci=None):
    """Add static route.

    :param addr:            Destination network.
    :param via:             Gateway address.
    :param metric:          Metric.
    :param remove:          True to remove route.
    :param pci:             Device to be used for outgoing packets.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    if addr == 'default':
        return (True, None)

    metric = ' metric %s' % metric if metric else ''
    op     = 'replace'

    cmd_show = "sudo ip route show exact %s %s" % (addr, metric)
    try:
        output = subprocess.check_output(cmd_show, shell=True).decode()
    except:
        return False

    lines = output.splitlines()
    next_hop = ''
    if lines:
        removed = False
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
        if not pci:
            cmd = "sudo ip route %s %s%s nexthop via %s %s" % (op, addr, metric, via, next_hop)
        else:
            tap = pci_to_tap(pci)
            cmd = "sudo ip route %s %s%s nexthop via %s dev %s %s" % (op, addr, metric, via, tap, next_hop)

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True).decode()
    except Exception as e:
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

    return True

def vpp_set_dhcp_detect(pci, remove):
    """Enable/disable DHCP detect feature.

    :param params: params:
                        pci     -  Interface PCI.
                        remove  - True to remove rule, False to add.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    op = 'del' if remove else ''

    sw_if_index = pci_to_vpp_sw_if_index(pci)
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
    sw_if_index = vpp_ip_to_sw_if_index(addr)
    if_vpp_name = vpp_sw_if_index_to_name(sw_if_index)
    policies = fwglobals.g.policies.policies_get()
    remove = not add

    for policy_id, priority in policies.items():
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
    # creates clone of the recieved message, so the rest functions can simply
    # modify it as they wish!
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    msg = _fix_aggregation_format(msg)
    msg = _fix_dhcp(msg)
    return msg


def frr_create_ospfd(frr_cfg_file, ospfd_cfg_file, router_id):
    '''Creates the /etc/frr/ospfd.conf file, initializes it with router id and
    ensures that ospf is switched on in the frr configuration'''

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

    # Ensure that ospfd is switched on in /etc/frr/daemons.
    subprocess.check_call('sudo sed -i -E "s/ospfd=no/ospfd=yes/" %s' % frr_cfg_file, shell=True)

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
        (_, _, dr_pci_before) = get_default_route()

        # Now go and apply the netplan
        #
        cmd = 'netplan apply'
        log_str = caller_name + ': ' + cmd if caller_name else cmd
        fwglobals.log.debug(log_str)
        os.system(cmd)
        time.sleep(1)  				# Give a second to Linux to configure interfaces

        # Netplan might change interface names, e.g. enp0s3 -> vpp0, so reset cache
        #
        fwglobals.g.cache.pcis = {}

        # Find out if the default route was changed. If it was - reconnect agent.
        #
        (_, _, dr_pci_after) = get_default_route()
        if dr_pci_before != dr_pci_after:
            fwglobals.log.debug(
                "%s: netplan_apply: default route changed (%s->%s) - reconnect" % \
                (caller_name, dr_pci_before, dr_pci_after))
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

def set_linux_reverse_path_filter(dev_name, on):
    """ set rp_filter value of Linux property

    : param dev_name : device name to set the property for
    : param on       : if on is False, disable rp_filter. Else, enable it
    """
    if dev_name == None:
        return None

    # For default interface skip the setting as it is redundant
    #
    _, metric = get_interface_gateway(dev_name)
    if metric == '' or int(metric) == 0:
        return None

    # Fetch current setting, so it could be restored later if needed.
    #
    current_val = None
    try:
        cmd = 'sysctl net.ipv4.conf.%s.rp_filter' % dev_name
        out = subprocess.check_output(cmd, shell=True).decode()  # 'net.ipv4.conf.enp0s9.rp_filter = 1'
        current_val = bool(out.split(' = ')[1])
    except Exception as e:
        fwglobals.log.error("set_linux_reverse_path_filter(%s): failed to fetch current value: %s" % (dev_name, str(e)))
        return None

    # Light optimization, no need to set the value
    #
    if current_val == on:
        return current_val

    # Finally set the value
    #
    val = 1 if on else 0
    os.system('sysctl -w net.ipv4.conf.%s.rp_filter=%d > /dev/null' % (dev_name, val))
    os.system('sysctl -w net.ipv4.conf.all.rp_filter=%d > /dev/null' % (val))
    os.system('sysctl -w net.ipv4.conf.default.rp_filter=%d > /dev/null' % (val))

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
        assigned_pcis    = [params['pci'] for params in assigned_list]

        for pci in linux_interfaces:
            if not pci in assigned_pcis:
                if pci_is_vmxnet3(pci):
                    os.system("ip link set dev %s up" % linux_interfaces[pci]['name'])

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
    for pci in linux_interfaces:
        name = linux_interfaces[pci]['name']
        addr = get_interface_address(name, log=False)
        addr = addr.split('/')[0] if addr else ''
        gw, metric = get_interface_gateway(name)

        res += 'addr:'    + addr + ','
        res += 'gateway:' + gw + ','
        res += 'metric:'  + metric + ','
        if gw and addr:
            _, public_ip, public_port, _ = fwglobals.g.stun_wrapper.find_addr(pci)
            res += 'public_ip:'   + public_ip + ','
            res += 'public_port:' + str(public_port) + ','

    hash = hashlib.md5(res.encode()).hexdigest()
    fwglobals.log.debug("get_reconfig_hash: %s: %s" % (hash, res))
    return hash

def vpp_nat_add_remove_interface(remove, pci, metric):
    default_gw = ''
    vpp_if_name_add = ''
    vpp_if_name_remove = ''
    metric_min = sys.maxsize

    dev_metric = int(metric or 0)

    fo_metric = get_wan_failover_metric(pci, dev_metric)
    if fo_metric != dev_metric:
        fwglobals.log.debug(
            "vpp_nat_add_remove_interface: pci=%s, use wan failover metric %d" % (pci, fo_metric))
        dev_metric = fo_metric

    # Find interface with lowest metric.
    #
    wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
    for wan in wan_list:
        if pci == wan['pci']:
            continue
        metric_cur_str = wan.get('metric')
        if metric_cur_str == None:
            continue
        metric_cur = int(metric_cur_str or 0)
        metric_cur = get_wan_failover_metric(wan['pci'], metric_cur)
        if metric_cur < metric_min:
            metric_min = metric_cur
            default_gw = wan['pci']

    if remove:
        if dev_metric < metric_min or not default_gw:
            vpp_if_name_remove = pci_to_vpp_if_name(pci)
        if dev_metric < metric_min and default_gw:
            vpp_if_name_add = pci_to_vpp_if_name(default_gw)

    if not remove:
        if dev_metric < metric_min and default_gw:
            vpp_if_name_remove = pci_to_vpp_if_name(default_gw)
        if dev_metric < metric_min or not default_gw:
            vpp_if_name_add = pci_to_vpp_if_name(pci)

    if vpp_if_name_remove:
        vppctl_cmd = 'nat44 add interface address %s del' % vpp_if_name_remove
        out = _vppctl_read(vppctl_cmd, wait=False)
        if out is None:
            return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    if vpp_if_name_add:
        vppctl_cmd = 'nat44 add interface address %s' % vpp_if_name_add
        out = _vppctl_read(vppctl_cmd, wait=False)
        if out is None:
            # revert 'nat44 add interface address del'
            if vpp_if_name_remove:
                vppctl_cmd = 'nat44 add interface address %s' % vpp_if_name_remove
                _vppctl_read(vppctl_cmd, wait=False)
            return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    return (True, None)

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
