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


dpdk = __import__('dpdk-devbind')

def get_device_logs(file, num_of_lines):
    """Get device logs.

    :param file:            File name.
    :param num_of_lines:    Number of lines.

    :returns: Return list.
    """
    try:
        cmd = "tail -{} {}".format(num_of_lines, file)
        res = subprocess.check_output(cmd, shell=True).splitlines()

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
        res = subprocess.check_output(cmd, shell=True).splitlines()
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
def pid_of(proccess_name):
    """Get pid of process.

    :param proccess_name:   Proccess name.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', proccess_name])
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
        routing_table = subprocess.check_output(['route', '-n']).split('\n')
        return routing_table
    except:
        return (None)

def get_default_route():
    """Get default route.

    :returns: tuple (<IP of GW>, <name of network interface>).
    """
    (via, dev, metric) = ("", "", 0xffffffff)
    try:
        output = os.popen('ip route list match default').read()
        if output:
            routes = output.splitlines()
            for r in routes:
                _dev = ''   if not 'dev '    in r else r.split('dev ')[1].split(' ')[0]
                _via = ''   if not 'via '    in r else r.split('via ')[1].split(' ')[0]
                _metric = 0 if not 'metric ' in r else int(r.split('metric ')[1].split(' ')[0])
                if _metric < metric:  # The default route among default routes is the one with the lowest metric :)
                    dev = _dev
                    via = _via
    except:
        return ("", "")
    return (via, dev)

def get_interface_gateway(if_name):
    """Get gateway.

    :returns: Gateway ip address.
    """
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

def get_all_interfaces():
    """ Get all interfaces from linux. For dev id with address family of AF_INET,
        also store gateway, if exists.
        : return : Dictionary of dev_id->IP,GW
    """
    dev_id_ip_gw = {}
    interfaces = psutil.net_if_addrs()
    for nicname, addrs in interfaces.items():
        dev_id = get_interface_dev_id(nicname)
        if dev_id == '':
            continue

        if is_lte_interface(dev_id) and vpp_does_run():
            tap_name = dev_id_to_tap(dev_id)
            if tap_name:
                nicname = tap_name
                addrs = interfaces.get(nicname)

        dev_id_ip_gw[dev_id] = {}
        dev_id_ip_gw[dev_id]['addr'] = ''
        dev_id_ip_gw[dev_id]['gw']   = ''
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address.split('%')[0]
                dev_id_ip_gw[dev_id]['addr'] = ip
                gateway, _ = get_interface_gateway(nicname)
                dev_id_ip_gw[dev_id]['gw'] = gateway if gateway else ''
                break

    return dev_id_ip_gw

def get_interface_address(if_name):
    """Get interface IP address.

    :param iface:        Interface name.

    :returns: IP address.
    """
    interfaces = psutil.net_if_addrs()
    if if_name not in interfaces:
        fwglobals.log.debug("get_interface_address(%s): interfaces: %s" % (if_name, str(interfaces)))
        return None

    addresses = interfaces[if_name]
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip   = addr.address
            mask = IPAddress(addr.netmask).netmask_bits()
            fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addr)))
            return '%s/%s' % (ip, mask)

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

def get_linux_dev_ids():
    """ Get the list of PCI-s of all network interfaces available in Linux.
    """
    dev_id_list = fwglobals.g.cache.dev_ids
    if not dev_id_list:
        interfaces = psutil.net_if_addrs()
        for (nicname, _) in interfaces.items():
            dev_id = get_interface_dev_id(nicname)
            if dev_id == "":
                continue
            dev_id_list.append(dev_id)
    return dev_id_list

def dev_id_parse(dev_id):
    """Convert a dev id into a tuple contained address type (pci, usb) and address.

    :param dev_id:     device bus address.

    :returns: Tuple (type, address)
    """
    type_and_addr = dev_id.split(':', 1)
    if type_and_addr:
        return (type_and_addr[0], type_and_addr[1])

    return ("", "")

def dev_id_add_type(dev_id):
    """Add address type at the begining of the address.

    :param dev_id:      device bus address.

    :returns: device bus address with type.
    """
    if dev_id.startswith('pci:') or dev_id.startswith('usb:'):
        return dev_id

    if re.search('usb', dev_id):
        return 'usb:%s' % dev_id

    return 'pci:%s' % dev_id

def get_linux_interfaces():
    """ Get the list of dev id's of all network interfaces available in Linux.
    """
    interfaces = fwglobals.g.cache.dev_ids
    if not interfaces:
        for (if_name, _) in psutil.net_if_addrs().items():
            dev_id = get_interface_dev_id(if_name)
            if not dev_id:
                continue
            interfaces[dev_id_to_full(dev_id)] = if_name
    return interfaces

def get_interface_dev_id(linuxif):
    """Convert Linux interface name into bus address.

    :param linuxif:      Linux interface name.

    :returns: dev_id.
    """
    NETWORK_BASE_CLASS = "02"
    vpp_run = vpp_does_run()
    lines = subprocess.check_output(["lspci", "-Dvmmn"]).splitlines()
    for line in lines:
        vals = line.decode().split("\t", 1)
        if len(vals) == 2:
            # keep slot number
            if vals[0] == 'Slot:':
                slot = vals[1]
            if vals[0] == 'Class:':
                if vals[1][0:2] == NETWORK_BASE_CLASS:
                    slot = dev_id_add_type(slot)
                    interface = dev_id_to_linux_if(slot)
                    if not interface and vpp_run:
                        interface = dev_id_to_tap(slot)
                    if not interface:
                        continue
                    if interface == linuxif:
                        return dev_id_to_full(slot)

    # in case of non-pci interface try to get from /sys/class/net
    try:
        if_addr = subprocess.check_output("sudo ls -l /sys/class/net/ | grep %s" % linuxif, shell=True)

        if re.search('usb', if_addr):
            address = 'usb%s' % re.search('usb(.+?)/net', if_addr).group(1)
            return dev_id_add_type(address)
        # elif re.search('pci', if_addr):
        #     address = if_addr.split('/net')[0].split('/')[-1]
        #     address = dev_id_add_type(address)
        #     return dev_id_to_full(address)
        # else:
        #     tap = tap_to_dev_id(if_addr)
    except:
        return ""

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
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + addr, shell=True)
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
        #output = subprocess.check_output("sudo ls -l /sys/bus/pci/devices/%s/driver | grep vmxnet3" % pci, shell=True)
        output = subprocess.check_output("sudo dpdk-devbind -s | grep -E '%s .*vmxnet3'" % addr, shell=True)
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

    vpp_tap_interfaces = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_tap_dump()
    for tap in vpp_tap_interfaces:
        dev_name = tap.dev_name.rstrip(' \t\r\n\0')
        linux_dev_name = dev_name.split('_')[-1]
        addr = get_interface_dev_id(linux_dev_name)
        vpp_name = vpp_sw_if_index_to_name(tap.sw_if_index)
        if vpp_name and addr:
            fwglobals.g.cache.dev_id_to_vpp_if_name[addr] = vpp_name
            fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_name] = addr

    shif = _vppctl_read('show hardware-interfaces')
    if shif == None:
        fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps: Error reading interface info")
    data = shif.splitlines()
    for intf in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
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
        pci_addr = pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.cache.dev_id_to_vpp_if_name[pci_addr] = vpp_if_name
        fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name] = pci_addr

    if dev_id:
        vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id)
        if vpp_if_name: return vpp_if_name
    elif vpp_if_name:
        dev_id = fwglobals.g.cache.vpp_if_name_to_dev_id.get(vpp_if_name)
        if dev_id: return dev_id

    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s) not found: sh hard: %s" % (dev_id, vpp_if_name, shif))
    fwglobals.log.debug("_build_dev_id_to_vpp_if_name_maps(%s, %s): not found sh vmxnet3: %s" % (dev_id, vpp_if_name, vmxnet3hw))
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
def dev_id_to_tap(dev_id):
    """Convert Bus address into TAP name.

    :param dev_id:      Bus address.
    :returns: Linux TAP interface name.
    """

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

def linux_tap_by_interface_name(linux_if_name):
    try:
        links = subprocess.check_output("sudo ip link | grep tap_%s" % linux_if_name, shell=True)
        lines = links.splitlines()

        for line in lines:
            words = line.split(': ')
            return words[1]
    except:
        return None

def configure_tap_in_linux_and_vpp(linux_if_name):
    """Create tap interface in linux and vpp.
      This function will create three interfaces:
        1. linux tap interface.
        2. vpp tap interface in vpp.
        3. linux interface for tap-inject.

    :param linux_if_name: name of the linux interface to create tap for

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    # length = str(len(vpp_if_name_to_pci))
    linux_tap_name = "tap_%s" % linux_if_name

    try:
        vpp_tap_connect(linux_tap_name)
        return (True, None)
    except Exception as e:
        return (False, "Failed to create tap interface for %s\nOutput: %s" % (linux_if_name, str(e)))

def vpp_tap_connect(linux_tap_if_name):
    """Run vpp tap connect command.
      This command will create a linux tap interface and also tapcli interface in vpp.
     :param linux_tap_if_name: name to be assigned to linux tap device

     :returns: VPP tap interface name.
     """

    vppctl_cmd = "tap connect %s" % linux_tap_if_name
    fwglobals.log.debug("vppctl " + vppctl_cmd)
    subprocess.check_output("sudo vppctl %s" % vppctl_cmd, shell=True).splitlines()

def vpp_add_static_arp(dev_id, gw, mac):
    try:
        vpp_if_name = dev_id_to_vpp_if_name(dev_id)
        vppctl_cmd = "set ip arp static %s %s %s" % (vpp_if_name, gw, mac)
        fwglobals.log.debug("vppctl " + vppctl_cmd)
        subprocess.check_output("sudo vppctl %s" % vppctl_cmd, shell=True).splitlines()
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
            addr = get_interface_address(tap)
            if addr:
                int_address = IPNetwork(addr)
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
    return mac_str.replace(':', '').decode('hex')

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
    p = FwStartupConf()
    config = p.load(vpp_config_filename)

    if config['dpdk'] == None:
        return
    for dev in devices:
        dev = dev_id_to_short(dev)
        addr_type, addr = dev_id_parse(dev)
        config_param = 'dev %s' % addr
        key = p.get_element(config['dpdk'],config_param)
        if key:
            p.remove_element(config['dpdk'], key)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_add_nat(vpp_config_filename):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)
    if config['nat'] == None:
        tup = p.create_element('nat')
        config.append(tup)
        config['nat'].append(p.create_element('endpoint-dependent'))
        config['nat'].append(p.create_element('translation hash buckets 1048576'))
        config['nat'].append(p.create_element('translation hash memory 268435456'))
        config['nat'].append(p.create_element('user hash buckets 1024'))
        config['nat'].append(p.create_element('max translations per user 10000'))

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_nat(vpp_config_filename):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)
    key = p.get_element(config, 'nat')
    if key:
        p.remove_element(config,key)
    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def get_lte_interfaces_names():
    names = []
    interfaces = psutil.net_if_addrs()

    for nicname, addrs in interfaces.items():
        dev_id = get_interface_dev_id(nicname)
        if dev_id and is_lte_interface(dev_id):
            names.append(nicname)

    return names

def traffic_control_add_del_dev_ingress(dev_name, is_add):
    try:
        subprocess.check_output('sudo tc -force qdisc %s dev %s ingress handle ffff:' % ('add' if is_add else 'delete', dev_name), shell=True)
        return (True, None)
    except Exception as e:
        return (True, None)

def traffic_control_replace_dev_root(dev_name):
    try:
        subprocess.check_output('sudo tc -force qdisc replace dev %s root handle 1: htb' % dev_name, shell=True)
        return (True, None)
    except Exception as e:
        return (True, None)

def traffic_control_remove_dev_root(dev_name):
    try:
        subprocess.check_output('sudo tc -force qdisc del dev %s root' % dev_name, shell=True)
        return (True, None)
    except Exception as e:
        return (True, None)

def reset_traffic_control():
    search = []
    lte_interfaces = get_lte_interfaces_names()

    if lte_interfaces:
        search.extend(lte_interfaces)

    for term in search:
        try:
            subprocess.check_output('sudo tc -force qdisc del dev %s root' % term, shell=True)
        except:
            pass

        try:
            subprocess.check_output('sudo tc -force qdisc del dev %s ingress handle ffff:' % term, shell=True)
        except:
            pass

    return True

def remove_linux_bridges():
    try:
        lines = subprocess.check_output('ls -l /sys/class/net/ | grep br_', shell=True).splitlines()

        for line in lines:
            bridge_name = line.rstrip().split('/')[-1]
            try:
                output = subprocess.check_output("sudo ip link set %s down " % bridge_name, shell=True)
            except:
                pass

            try:
                subprocess.check_output('sudo brctl delbr %s' % bridge_name, shell=True)
            except:
                pass
        return True
    except:
        return True

def reset_dhcpd():
    if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP, fwglobals.g.DHCPD_CONFIG_FILE)

    cmd = 'sudo systemctl stop isc-dhcp-server'

    try:
        output = subprocess.check_output(cmd, shell=True)
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

    # Add interface name in case of wifi interface
    if is_wifi_interface(dev_id):
        intf_name = dev_id_to_linux_if(dev_id)
        intf_string = 'interface %s;\n' % intf_name
    else:
        intf_string = ''

    subnet_string = 'subnet %s netmask %s' % (subnet, netmask)
    routers_string = 'option routers %s;\n' % (router)
    dhcp_string = 'echo "' + subnet_string + ' {\n' + intf_string + range_string + \
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
        output = subprocess.check_output(exec_string, shell=True)
    except Exception as e:
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

    return True

def vpp_multilink_update_labels(labels, remove, next_hop=None, dev=None, sw_if_index=None):
    """Updates VPP with flexiwan multilink labels.
    These labels are used for Multi-Link feature: user can mark interfaces
    or tunnels with labels and than add policy to choose interface/tunnel by
    label where to forward packets to.

        REMARK: this function is temporary solution as it uses VPP CLI to
    configure lables. Remove it, when correspondent Python API will be added.
    In last case the API should be called directly from translation.

    :param params: labels      - python list of labels
                   is_dia      - type of labels (DIA - Direct Internet Access)
                   remove      - True to remove labels, False to add.
                   dev         - Bus address of Device to apply labels to.
                   next_hop_ip - IP address of next hop.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels, remove)
    ids = ','.join(map(str, ids_list))

    if dev:
        vpp_if_name = dev_id_to_vpp_if_name(dev)
    elif sw_if_index:
        vpp_if_name = vpp_sw_if_index_to_name(sw_if_index)
    else:
        return (False, "Neither 'dev' nor 'sw_if_index' was found in params")

    if not vpp_if_name:
        return (False, "'vpp_if_name' was not found for %s" % dev)

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

def get_interface_sw_if_index(ip):
    """Convert interface src IP address into gateway VPP sw_if_index.

    :param ip: IP address.

    :returns: sw_if_index.
    """
    dev_id, _ = fwglobals.g.router_cfg.get_wan_interface_gw(ip)
    if not dev_id:
        # If interface was configured with dhcp, router_cfg has no IP-s.
        # In this case try to fetch GW from Linux.
        if_name = get_interface_name(ip)
        if if_name:
            dev_id = get_interface_dev_id(if_name)
            if not dev_id:
                cache = fwglobals.g.cache.dev_id_to_vpp_tap_name
                for dev in cache:
                    if cache[dev] == if_name:
                        dev_id = dev
    if not dev_id:
        return None
    return dev_id_to_vpp_sw_if_index(dev_id)

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

def get_interface_gateway_from_router_db(ip):
    """Convert interface src IP address into gateway IP address.

    :param ip: IP address.

    :returns: IP address.
    """
    _, gw_ip = fwglobals.g.router_cfg.get_wan_interface_gw(ip)
    if not gw_ip:
        # If interface was configured with dhcp, router_cfg has no IP-s.
        # In this case try to fetch GW from Linux.
        if_name = get_interface_name(ip)
        if if_name:
            gw_ip, _ = get_interface_gateway(if_name)
    if not gw_ip:
        return None
    return ip_str_to_bytes(gw_ip)[0]

def add_static_route(addr, via, metric, remove, dev_id=None):
    """Add static route.

    :param params: params:
                        addr    - Destination network.
                        via     - Gateway address.
                        metric  - Metric.
                        remove  - True to remove route.
                        dev_id  - Bus address of device to be used for outgoing packets.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    if addr == 'default':
        return (True, None)

    metric = ' metric %s' % metric if metric else ''
    op     = 'replace'

    cmd_show = "sudo ip route show exact %s %s" % (addr, metric)
    try:
        output = subprocess.check_output(cmd_show, shell=True)
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
        if not dev_id:
            cmd = "sudo ip route %s %s%s nexthop via %s %s" % (op, addr, metric, via, next_hop)
        else:
            tap = dev_id_to_tap(dev_id)
            cmd = "sudo ip route %s %s%s nexthop via %s dev %s %s" % (op, addr, metric, via, tap, next_hop)

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True)
    except Exception as e:
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
    sw_if_index = vpp_ip_to_sw_if_index(addr)
    if_vpp_name = vpp_sw_if_index_to_name(sw_if_index)
    policies = fwglobals.g.policies.policies_get()
    remove = not add

    for policy_id, priority in policies.items():
        vpp_multilink_attach_policy_rule(if_vpp_name, int(policy_id), priority, 0, remove)

def fix_request_params(params, message=None):
    """ Fix incoming message parameters
    The purpose of this function is to fix 'params' that contains the pci as interface identification.
    The function changes the pci address into `dev_id` which is the new interface identifier.
    Since we have different types of `params` object,
    we need to use several if/else statements in order to handle all of them.

    :param params - parameters object.
    :param message - request message.

    """

    def _fix_params_key(params, key, message=None):
        if key in params:
            if type(params[key]) == list:
                params['dev_id'] = [dev_id_add_type(pci) for pci in params[key]]
                del params[key]
            else:
                params['dev_id'] = dev_id_add_type(params.pop(key))

        if message and re.match('(add|remove)-dhcp-config', message) and 'interface' in params:
            params['interface'] = dev_id_add_type(params['interface'])

        return params


    if 'requests' in params:
        requests = params['requests']
        for request in requests:
            if 'params' in request:
                request['params'] = _fix_params_key(request['params'], 'pci', request['message'])
                request['params'] = _fix_params_key(request['params'], 'devId', request['message'])

    if 'pci' in params:
        params = _fix_params_key(params, 'pci')

    if 'devId' in params:
        params = _fix_params_key(params, 'devId')

    if 'args' in params and 'params' in params['args']:
        nested_params = params['args']['params']
        if 'interface' in nested_params:
            nested_params['interface'] = dev_id_add_type(nested_params['interface'])

    if message and re.match('(add|remove)-dhcp-config', message) and 'interface' in params:
        params['interface'] = dev_id_add_type(params['interface'])

    return params

def fix_message(msg):
    msg = fix_aggregated_message_format(msg)

    if 'params' in msg:
        msg['params'] = fix_request_params(msg['params'], msg['message'])

    return msg

# Today (May-2019) message aggregation is not well defined in protocol between
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
def fix_aggregated_message_format(msg):

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

def wifi_get_available_networks(dev_id):
    """Get WIFI available access points.

    :param dev_id: Bus address of interface to get for.

    :returns: string array of essids
    """
    linux_if = dev_id_to_linux_if(dev_id)

    if linux_if:
        networks = []

        def clean(n):
            n = n.replace('"', '')
            n = n.strip()
            n = n.split(':')[-1]
            return n

        # make sure the interface is up
        cmd = 'ip link set dev %s up' % linux_if
        subprocess.check_output(cmd, shell=True)

        try:
            cmd = 'iwlist %s scan | grep ESSID' % linux_if
            networks = subprocess.check_output(cmd, shell=True).splitlines()
            networks = map(clean, networks)
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
        subprocess.check_output('wpa_passphrase %s %s | sudo tee /etc/wpa_supplicant.conf' % (essid, password), shell=True)

        try:
            output = subprocess.check_output('wpa_supplicant -i %s -c /etc/wpa_supplicant.conf -D wext -B -C /var/run/wpa_supplicant' % interface_name, shell=True)
            time.sleep(3)

            is_success = subprocess.check_output('wpa_cli  status | grep wpa_state | cut -d"=" -f2', shell=True)

            if is_success.strip() == 'COMPLETED':

                if params['useDHCP']:
                    subprocess.check_output('dhclient %s' % interface_name, shell=True)

                return True
            else:
                return False
        except subprocess.CalledProcessError:
            return False

    return False

def is_lte_interface(dev_id):
    """Check if interface is LTE.

    :param dev_id: Bus address of interface to check.

    :returns: Boolean.
    """
    driver = get_interface_driver(dev_id)
    supported_lte_drivers = ['cdc_mbim']
    if driver in supported_lte_drivers:
        return True

    return False

def lte_get_saved_apn():
    cmd = 'cat /etc/mbim-network.conf'
    try:
        out = subprocess.check_output(cmd, shell=True).strip()
        configs = out.split('=')
        if configs[0] == "APN":
            return configs[1]
        return ''
    except subprocess.CalledProcessError:
        return ''

    return ''

def lte_dev_id_to_iface_addr_bytes(dev_id):
    if is_lte_interface(dev_id):
        info = lte_get_configuration_received_from_provider()
        return ip_str_to_bytes(info['IP'])[0]

    return None

def configure_hostapd(dev_id, configuration):
    try:

        config = {
            'ssid'                 : configuration.get('ssid', 'fwrouter_ap'),
            'wpa_passphrase'       : configuration.get('password', 'fwrouter_ap'),
            'interface'            : dev_id_to_linux_if(dev_id),
            'channel'              : 6,
            'macaddr_acl'          : 0,
            'hw_mode'              : configuration.get('operationMode', 'g'),
            'ignore_broadcast_ssid': 0,
            'driver'               : 'nl80211',
            'auth_algs'            : 1,
            'eap_server'           : 0,
            'wmm_enabled'          : 0,
            'wpa'                  : 2,
            'wpa_pairwise'         : 'TKIP',
            'rsn_pairwise'         : 'CCMP',
            'logger_syslog'        : -1,
            'logger_syslog_level'  : 2,
            'logger_stdout'        : -1,
            'logger_stdout_level'  : 2
        }

        with open(fwglobals.g.HOSTAPD_CONFIG_FILE, 'w+') as f:
            data = ''
            for key in config:
                data += '%s=%s\n' % (key, config[key])

            file_write_and_flush(f, data)

        # driver = if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):


        # config_file = 

        return (True, None)
    except Exception as e:
        return (False, "Exception: %s" % str(e))

def start_hostapd():
    try:
        os.system('sudo hostapd -d /etc/hostapd/hostapd.conf -B')
        return (True, None)
    except Exception as e:
        return (False, "Exception: %s" % str(e))

def stop_hostapd():
    try:
        os.system('killall hostapd')
        return (True, None)
    except Exception as e:
        return (False, "Exception: %s" % str(e))

def get_inet6_by_linux_name(inf_name):
    interfacaes = psutil.net_if_addrs()
    if inf_name in interfacaes:
        for addr in interfacaes[inf_name]:
            if addr.family == socket.AF_INET6:
                inet6 = addr.address.split('%')[0]
                if addr.netmask != None:
                    inet6 += "/" + (str(IPAddress(addr.netmask).netmask_bits()))
                return inet6

    return None

def set_lte_info_on_linux_interface():
    interfacaes = psutil.net_if_addrs()
    for nicname, addrs in interfacaes.items():
        dev_id = get_interface_dev_id(nicname)
        if dev_id and is_lte_interface(dev_id):
            ip_info = lte_get_configuration_received_from_provider()
            if ip_info['STATUS']:
                os.system('ifconfig %s %s up' % (nicname, ip_info['IP']))
                os.system('route add -net 0.0.0.0 gw %s' % ip_info['GATEWAY'])

    return None

# def lte_get_status():
    # RSSI - query by mbimcli --device /dev/cdc-wdm0 --query-signal-state  --no-open=3 --no-close
    # 2 - 9 Marginal
    # 10 - 14 OK
    # 15 - 19 Good
    # 20 - 30 Excellent

    # RSSI to dbm = 2n - 113 - e.g. RSSI 10: (10 * 2) - 113 = -93 dbm)
    #


def mbim_is_open():
    '''
    The function will check if there is an open session to the modem.
    This done by set the no-open flag, to try send a command without open a new session.
    If it fails, it means that no exists session is already open

    :returns: boolean indicates if an open session is already exists
    '''
    try:
        output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status --no-close --no-open=1', shell=True, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError as err:
        return False

def mbim_open_new_session():
    '''
    The function will open a new session to the modem without closing it.
    '''
    try:
        subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status --no-close', shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        raise err

def mbim_close_opened_session():
    '''
    The function will close existing opened session
    '''
    try:
        subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status', shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        pass

    return True

def mbim_get_signals_state(force_new_session=False):
    try:
        if not mbim_is_open() or force_new_session:
            mbim_open_new_session()

        output = subprocess.check_output('mbimcli --device /dev/cdc-wdm0 --query-signal-state  --no-open=3 --no-close', shell=True, stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as err:
        return None

def mbim_get_home_provider(force_new_session=False):
    '''
    The function retrive the home provider burn on the sim
    '''
    try:
        if not mbim_is_open() or force_new_session:
            mbim_open_new_session()

        output = subprocess.check_output('mbimcli --device /dev/cdc-wdm0 --query-home-provider --no-open=3 --no-close', shell=True, stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as err:
        return None

def mbim_get_connection_state(force_new_session=False):
    '''
    The function will return the connection status.
    This is not about existsin session to the modem. But connectivity between modem to the cellular provider
    '''
    try:
        if not mbim_is_open() or force_new_session:
            mbim_open_new_session()

        output = subprocess.check_output('mbimcli --device /dev/cdc-wdm0 --query-connection-state --no-open=3 --no-close', shell=True, stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as err:
        return None

def mbim_get_ip_configuration(force_new_session=False):
    '''
    The function will return the connection status.
    This is not about existsin session to the modem. But connectivity between modem to the cellular provider
    '''
    try:
        if not mbim_is_open() or force_new_session:
            mbim_open_new_session()

        current_connection_state = mbim_get_connection_state()
        if current_connection_state and 'deactivated' in current_connection_state:
            return None

        output = subprocess.check_output('mbimcli --device /dev/cdc-wdm0 --query-ip-configuration --no-open=3 --no-close', shell=True, stderr=subprocess.STDOUT)
        return output
    except subprocess.CalledProcessError as err:
        return None


def lte_connect(apn, dev_id):
    if not apn:
        return (False, "apn is not configured for %s" % dev_id)

    try:
        current_connection_state = mbim_get_connection_state()
        if current_connection_state and not 'deactivated' in current_connection_state:
            return (True, None)

        output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-registration-state --no-open=3 --no-close', shell=True, stderr=subprocess.STDOUT)
        output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --attach-packet-service --no-open=4 --no-close', shell=True, stderr=subprocess.STDOUT)
        output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --connect=apn=%s,ip-type=ipv4 --no-open=5 --no-close' % apn, shell=True, stderr=subprocess.STDOUT)
        ip_info = mbim_get_ip_configuration()
        return (True, None)
    except subprocess.CalledProcessError as e:
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

def lte_get_configuration_received_from_provider():
    try:
        response = {
            'IP'      : '',
            'GATEWAY' : '',
            'STATUS'  : ''
        }

        ip_info = mbim_get_ip_configuration()

        if ip_info:
            response['STATUS'] = True
            lines = ip_info.splitlines()
            for line in lines:
                if 'IP [0]' in line:
                    response['IP'] = line.split(':')[-1].strip().replace("'", '')
                    continue
                if 'Gateway' in line:
                    response['GATEWAY'] = line.split(':')[-1].strip().replace("'", '')
                    continue

            return response
    except Exception as e:
        return response

def lte_get_provider_config(key):
    """Get IP from LTE provider

    :param ket: Filter info by key

    :returns: ip address.
    """
    info = lte_get_configuration_received_from_provider()

    if key:
        return info[key]

    return info

# def lte_update_params(orig_req_params, dev_id):
#     info = lte_get_configuration_received_from_provider()
#     orig_req_params['addr'] = unicode(info['IP'])
#     orig_req_params['gateway'] = unicode(info['GATEWAY'])

#     tap = dev_id_to_tap(dev_id)
#     inet6 = get_inet6_by_linux_name(tap)
#     if inet6:
#         orig_req_params['addr6'] = unicode(inet6)

# def disconnect_from_lte():
#     try:
#         output = subprocess.check_output('mbim-network /dev/cdc-wdm0 stop', shell=True)
#         return (True, None)
#     except Exception as e:
#         return (False, "Exception: %s\nOutput: %s" % (str(e), output))

# def connect_to_lte(params):
#     interface_name = dev_id_to_linux_if(params['dev_id'])
#     apn = params['apn']

#     if not apn:
#         return (False, "apn is not configured for %s interface" % interface_name)


#     def _run_mbim_command(cmd):
#         try:
#             output = subprocess.check_output(cmd, shell=True)
#         except Exception as e:
#             if "Session not closed" in str(e.output):
#                 session = e.output.split("TRID: '")[-1]
#                 session_number = session.replace("'", "")
#                 try:
#                     output = subprocess.check_output(cmd + '--no-open=%s' % session_number , shell=True)
#                 except Exception as e:
#                     pass

#     num_retries = 3
#     for i in range(num_retries):
#         try:
#             output = subprocess.check_output('echo "APN=%s" > /etc/mbim-network.conf' % apn, shell=True)

#             _run_mbim_command('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status --no-close')
#             _run_mbim_command('mbimcli -d /dev/cdc-wdm0 --query-registration-state --no-open=3 --no-close')
#             _run_mbim_command('mbimcli -d /dev/cdc-wdm0 --attach-packet-service --no-open=4 --no-close')
#             _run_mbim_command('mbimcli -d /dev/cdc-wdm0 --connect=apn=%s,ip-type=ipv4 --no-open=5 --no-close > /tmp/wwan-ip' % apn)

#             # output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status --no-close', shell=True)
#             # output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-registration-state --no-open=3 --no-close', shell=True)
#             # output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --attach-packet-service --no-open=4 --no-close', shell=True)
#             # output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --query-subscriber-ready-status --no-close', shell=True)
#             # output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --connect=apn=%s,ip-type=ipv4 --no-open=5 --no-close > /tmp/wwan-ip' % apn, shell=True)

#             info = lte_get_configuration_received_from_provider()

#             if info['STATUS'] == True:
#                 return (True, None)
#         except Exception as e:
#             if i == num_retries-1:
#                 return (False, "Exception: %s\nOutput: %s" % (str(e), output))
#             else:
#                 # time.sleep(1)
#                 # if "Session not close" in str(e.output):
#                 #     try:
#                 #         output = subprocess.check_output(e.cmd, shell=True)
#                 #         output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --disconnect=4', shell=True)
#                 #         output = subprocess.check_output('mbimcli -d /dev/cdc-wdm0 --disconnect=5', shell=True)
#                 #     except Exception as e:
#                 pass

#     return (False, "Couldn't connect to lte provider")

def is_wifi_interface(dev_id):
    """Check if interface is WIFI.

    :param interface_name: Interface name to check.

    :returns: Boolean.
    """
    linux_if = dev_id_to_linux_if(dev_id)

    if linux_if:
        cmd = 'cat /proc/net/wireless | grep %s' % linux_if
        try:
            out = subprocess.check_output(cmd, shell=True).strip()
            return True
        except subprocess.CalledProcessError:
            return False

    return False

def get_interface_driver(dev_id):
    """Get Linux interface driver.

    :param dev_id: Bus address of interface to check.

    :returns: driver name.
    """

    linux_if = dev_id_to_linux_if(dev_id)
    if linux_if:
        try:
            cmd = 'ethtool -i %s' % linux_if
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).splitlines()
            vals = out[0].decode().split("driver: ", 1)
            return str(vals[-1])
        except subprocess.CalledProcessError:
            return ''

    return ''

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

    if is_wifi_interface(dev_id):
        return True
    if is_lte_interface(dev_id):
        return True

    return False

def get_bus_info(interface_name):
    """Get LTE device bus info.

    :param interface_name: Interface name to check.

    :returns: bus_info .
    """
    try:
        cmd = 'ethtool -i %s' % interface_name
        out = subprocess.check_output(cmd, shell=True).splitlines()
        vals = out[4].decode().split("bus-info: ", 1)
        return str(vals[-1])
    except subprocess.CalledProcessError:
        return ''

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
    cmd = 'netplan apply'
    log_str = caller_name + ': ' + cmd if caller_name else cmd
    fwglobals.log.debug(log_str)
    os.system(cmd)
    time.sleep(1)  # Give a second to Linux to configure interfaces

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
        if val1 and val2:   # Both values are neither None-s nor empty strings.
            if type(val1) != type(val2):
                return False        # Not comparable types
            if type(val1) == str:
                if val1.lower() != val2.lower():
                    return False    # Strings are not equal
            elif val1 != val2:
                return False        # Values are not equal
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
        return

    _, metric = get_interface_gateway(dev_name)
    # for default interface, skip the setting as it is redundant
    if metric == '' or int(metric) == 0:
        return

    val = 1 if on else 0

    os.system('sysctl -w net.ipv4.conf.%s.rp_filter=%d' %(dev_name, val))
    os.system('sysctl -w net.ipv4.conf.all.rp_filter=%d' %(val))
    os.system('sysctl -w net.ipv4.conf.default.rp_filter=%d' %(val))

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
                    os.system("ip link set dev %s up" % linux_interfaces[dev_id])

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
        name = linux_interfaces[dev_id]

        if is_lte_interface(dev_id) and vpp_does_run():
            tap_name = dev_id_to_tap(dev_id)
            if tap_name:
                name = tap_name

        addr = get_interface_address(name)
        addr = addr.split('/')[0] if addr else ''
        gw, metric = get_interface_gateway(name)

        res += 'addr:'    + addr + ','
        res += 'gateway:' + gw + ','
        res += 'metric:'  + metric + ','
        if gw and addr:
            _, public_ip, public_port, nat_type =fwglobals.g.stun_wrapper.find_addr(dev_id)
            res += 'public_ip:'   + public_ip + ','
            res += 'public_port:' + str(public_port) + ','

    hash = hashlib.md5(res).hexdigest()
    return hash

def vpp_nat_add_remove_interface(remove, dev_id, metric):
    default_gw = ''
    vpp_if_name_add = ''
    vpp_if_name_remove = ''
    metric_min = -1

    dev_metric = int(metric or 0)
    wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')

    for wan in wan_list:
        metric_cur_str = wan.get('metric', None)
        if not metric_cur_str:
            continue

        metric_cur = int(metric_cur_str or 0)
        wan_dev_id = wan['dev_id']

        if wan_dev_id == dev_id:
            continue

        if metric_min == -1 or metric_min > metric_cur:
            metric_min = metric_cur
            default_gw = wan_dev_id

    if remove:
        if dev_metric < metric_min or not default_gw:
            vpp_if_name_remove = dev_id_to_vpp_if_name(dev_id)
        if dev_metric < metric_min and default_gw:
            vpp_if_name_add = dev_id_to_vpp_if_name(default_gw)

    if not remove:
        if dev_metric < metric_min and default_gw:
            vpp_if_name_remove = dev_id_to_vpp_if_name(default_gw)
        if dev_metric < metric_min or not default_gw:
            vpp_if_name_add = dev_id_to_vpp_if_name(dev_id)

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

def wifi_get_capabilities(dev_id):

    result = {
        'SupportedModes': [],
        'Band 1': {
            'Frequencies': [],
            'Bitrates': [],
            'Exists': False
        },
        'Band 2': {
            'Frequencies': [],
            'Capabilities': [],
            'Bitrates': [],
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
        regex = text + r'.*?(\\n\\t(?!' + (r'\\t' * negative_look_count) + '))'
        match = re.search(regex, output,  re.MULTILINE | re.IGNORECASE)

        res = list()

        if match:
            result = match.group()
            splitted = result.replace('\\t', '\t').replace('\\n', '\n').splitlines()
            for line in splitted[1:-1]:
                res.append(line.lstrip('\t').strip(' *'))
            return res

        return res

    try:
        output = subprocess.check_output('iw dev', shell=True).splitlines()
        linux_if = dev_id_to_linux_if(dev_id)
        if linux_if in output[1]:
            phy_name = output[0].replace('#', '')
            #output = subprocess.check_output('cat /tmp/jaga', shell=True).replace('\\\\t', '\\t').replace('\\\\n', '\\n')
            # banda1 = _get_band(output2, 1)
            # banda2 = _get_band(output2, 2)

            output = subprocess.check_output('iw %s info' % phy_name, shell=True).replace('\t', '\\t').replace('\n', '\\n')
            result['SupportedModes'] = _parse_key_data('Supported interface modes', output)


            band1 = _get_band(output, 1)
            band2 = _get_band(output, 2)

            if band1:
                result['Band 1']['Exists'] = True
                result['Band 1']['Frequencies'] = _parse_key_data('Frequencies', band1)
                result['Band 1']['Bitrates'] = _parse_key_data('Bitrates', band1, 2)
                result['Band 1']['Capabilities'] = _parse_key_data('Capabilities', band1, 2)

            if band2:
                result['Band 2']['Exists'] = True
                result['Band 2']['Frequencies'] = _parse_key_data('Frequencies', band2)
                result['Band 2']['Bitrates'] = _parse_key_data('Bitrates', band2, 2)
                result['Band 2']['Capabilities'] = _parse_key_data('Capabilities', band2, 2)

        return result
    except Exception as e:
        return result
