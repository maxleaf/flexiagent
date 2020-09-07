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
import serial
from netaddr import IPNetwork, IPAddress

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools' , 'common')
sys.path.append(common_tools)
from fw_vpp_startupconf import FwStartupConf

from fwapplications import FwApps
from fwrouter_cfg   import FwRouterCfg
from fwmultilink    import FwMultilink


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

    :returns: Default route.
    """
    try:
        output = os.popen('ip route list match default').read()
        if output:
            routes = output.splitlines()
            if routes:
                route = routes[0]
                dev_split = route.split('dev ')
                rdev = dev_split[1].split(' ')[0] if len(dev_split) > 1 else ''
                rip_split = route.split('via ')
                rip = rip_split[1].split(' ')[0] if len(rip_split) > 1 else ''
                return (rip, rdev)
    except:
        return ("", "")
    return ("", "")

def get_linux_interface_gateway(if_name):
    """Get gateway.

    :returns: Gateway ip address.
    """
    try:
        dgw = os.popen('ip route list match default | grep via').read()
    except:
        return '', ''

    metric = ''

    routes = dgw.splitlines()
    for route in routes:
        rip = route.split('via ')[1].split(' ')[0]
        rdev = route.split('dev ')[1].split(' ')[0]
        metric_str = route.split('metric ')
        if len(metric_str) > 1:
            metric = route.split('metric ')[1].split(' ')[0]
        if re.match(if_name, rdev):
            return rip, metric

    return '', ''

def get_interface_address(if_name):
    """Get interface IP address.

    :param iface:        Interface name.

    :returns: IP address.
    """
    interfaces = psutil.net_if_addrs()
    if if_name not in interfaces:
        fwglobals.log.debug("get_interface_address(%s): interfaces: %s" % (if_name, str(interfaces)))
        return ''

    addresses = interfaces[if_name]
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip   = addr.address
            mask = IPAddress(addr.netmask).netmask_bits()
            return '%s/%s' % (ip, mask)

    fwglobals.log.debug("get_interface_address(%s): %s" % (if_name, str(addresses)))
    return None

def is_ip_in_subnet(ip, subnet):
    """Check if IP address is in subnet.

    :param ip:            IP address.
    :param subnet:        Subnet address.

    :returns: 'True' if address is in subnet.
    """
    return True if IPAddress(ip) in IPNetwork(subnet) else False

def pci_addr_full(pci_addr):
    """Convert short PCI into full representation.

    :param pci_addr:      Short PCI address.

    :returns: Full PCI address.
    """
    pc = pci_addr.split('.')
    if len(pc) == 2:
        return pc[0]+'.'+"%02x"%(int(pc[1],16))
    return pci_addr

# Convert 0000:00:08.01 provided by management to 0000:00:08.1 used by Linux
def pci_full_to_short(pci):
    """Convert full PCI into short representation.

    :param pci_addr:      Full PCI address.

    :returns: Short PCI address.
    """
    l = pci.split('.')
    if len(l[1]) == 2 and l[1][0] == '0':
        pci = l[0] + '.' + l[1][1]
    return pci

def linux_to_pci_addr(linuxif):
    """Convert Linux interface name into PCI address.

    :param linuxif:      Linux interface name.

    :returns: PCI address.
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
                    interface = pci_to_linux_iface(slot)
                    if not interface and vpp_run:
                        interface = pci_to_tap(slot)
                    if not interface:
                        continue
                    if interface == linuxif:
                        driver = os.path.realpath('/sys/bus/pci/devices/%s/driver' % slot).split('/')[-1]
                        return (pci_addr_full(slot), "" if driver=='driver' else driver)
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
    pci = pci_full_to_short(pci)

    try:
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + pci, shell=True)
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
    pci = pci_full_to_short(pci)

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
    pci = pci_addr_full(pci)
    vpp_if_name = fwglobals.g.get_cache_data('PCI_TO_VPP_IF_NAME_MAP').get(pci)
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
    pci = fwglobals.g.get_cache_data('VPP_IF_NAME_TO_PCI_MAP').get(vpp_if_name)
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
            fwglobals.g.get_cache_data('PCI_TO_VPP_IF_NAME_MAP')[pci_addr_full(k)] = v
            fwglobals.g.get_cache_data('VPP_IF_NAME_TO_PCI_MAP')[v] = pci_addr_full(k)

    vmxnet3hw = fwglobals.g.router_api.vpp_api.vpp.api.vmxnet3_dump()
    for hw_if in vmxnet3hw:
        vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
        pci_addr = pci_bytes_to_str(hw_if.pci_addr)
        fwglobals.g.get_cache_data('PCI_TO_VPP_IF_NAME_MAP')[pci_addr] = vpp_if_name
        fwglobals.g.get_cache_data('VPP_IF_NAME_TO_PCI_MAP')[vpp_if_name] = pci_addr

    if pci:
        vpp_if_name = fwglobals.g.get_cache_data('PCI_TO_VPP_IF_NAME_MAP').get(pci)
        if vpp_if_name: return vpp_if_name
    elif vpp_if_name:
        pci = fwglobals.g.get_cache_data('VPP_IF_NAME_TO_PCI_MAP').get(vpp_if_name)
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
    vpp_if_name = pci_to_vpp_if_name(pci)
    if vpp_if_name is None:
        return None
    tap = vpp_if_name_to_tap(vpp_if_name)
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
            int_address = IPNetwork(get_interface_address(tap))
            if network == int_address:
                return sw_if.sw_if_index

def save_file(txt, fname, dir='/tmp'):
    """Save txt to file under a dir (default = /tmp)

     :param txt:      Text.
     :param fname:    File name.
     :param dir:      Folder path.

     :returns: Error message and status code.
     """
    # Make sure fname doesn't include /
    #print ("fname="+fname+", txt="+txt+", dir="+dir)
    if not (isinstance(fname, str) or isinstance(fname, unicode)) or fname.find('/') != -1:
        return {'message':'File name error', 'ok':0}
    datapath = os.path.join(dir, fname)
    if os.path.exists(dir):
        with open(datapath, 'w') as fout:
            fout.write(txt)
        return {'message':'File written', 'ok':1}
    else:
        return {'message':'Directory not exist', 'ok':0}

def _sub_file(fname, smap):
    """Replace words in file.

    :param fname:     File name.
    :param smap:      Dictionary with original and new words.

    :returns: Error message and status code.
    """
    if os.path.exists(fname):
        with open(fname, "r") as sfile:
            data = sfile.readlines()
        txt = ''.join(data)
        for k,v in smap.items():
            txt = txt.replace(k,v)
        with open(fname, "w") as sfile:
            sfile.write(txt)
        return {'message':'File substituted', 'ok':1}
    else:
        return {'message':'File does not exist', 'ok':0}

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

def tap_sub_file(fname):
    """Substitute a file with tap VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    taps = _vppctl_read('sh tap-inject')
    if taps == None:
        return {'message':'Tap read error', 'ok':0}
    if_map = {}
    tap_split = taps.split('\r\n')[:-1]
    if len(tap_split) == 0:
        return {'message':'No taps found', 'ok':0}
    for m in tap_split:
        ifs = m.split(' -> ')
        if len(ifs) != 2:
            return {'message':'Tap mapping error', 'ok':0}
        if_map[ifs[0]] = ifs[1]
    return _sub_file(fname, if_map)

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

def pci_sub_file(fname):
    """Substitute a file with pci address to VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    shif = _vppctl_read('show hardware-interfaces')
    shif_vmxnet3 = _vppctl_read('show vmxnet3')
    if shif == None or shif_vmxnet3 == None:
        return {'message':'Error reading interface info', 'ok':0}
    data = shif.splitlines()
    datav = shif_vmxnet3.splitlines()
    pci_map = {}
    for intf in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
            valregex=r"^(\w[^\s]+)\s+\d+\s+(\w+)",
            keyregex=r"\s+pci:.*\saddress\s(.*?)\s")
        if k and v: pci_map[pci_addr_full(k)] = v
    for intf in _get_group_delimiter(datav, r"^Interface:\s\w.*?\d"):
        # Contains data for a given interface
        ifdata = '\n'.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
            valregex=r"^Interface:\s(\w[^\s]+)\s+",
            keyregex=r"\s+PCI\sAddress:\s(.*)")
        if k and v: pci_map[pci_addr_full(k)] = v

    return _sub_file(fname, pci_map)

def gre_sub_file(fname):
    """Substitute a file with tunnels to VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    shtun = _vppctl_read('show ipsec gre tunnel')
    if shtun == None:
        return {'message':'Error reading tunnel info', 'ok':0}
    data = shtun.splitlines()
    tres = {}
    for tunnel in _get_group_delimiter(data, r"^\[\d+\].*"):
        # Contains data for a given tunnel
        tunneldata = '\n'.join(tunnel)
        (k,v) = _parse_vppname_map(tunneldata,
                       valregex=r"^\[(\d+)\].*local-sa",
                       keyregex=r"^\[\d+\].*local-sa\s(\d+)\s")
        if k and v: tres["ipsec-gre-"+k] = "ipsec-gre" + v
    return _sub_file(fname, tres)

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

def connect_to_router():
    """Connect to VPP Python API.

     :returns: None.
     """
    fwglobals.g.router_api.vpp_api.connect()

def disconnect_from_router():
    """Disconnect from VPP Python API.

     :returns: None.
     """
    fwglobals.g.router_api.vpp_api.disconnect()

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
        config_param = 'dev %s' % dev
        if p.get_element(config['dpdk'],config_param) == None:
            tup = p.create_element(config_param)
            config['dpdk'].append(tup)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_devices(vpp_config_filename, devices):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)

    if config['dpdk'] == None:
        return
    for dev in devices:
        config_param = 'dev %s' % dev
        key = p.get_element(config['dpdk'],config_param)
        if key:
            p.remove_element(config['dpdk'], key)

    p.dump(config, vpp_config_filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_add_nat(vpp_config_filename):
    p = FwStartupConf()
    config = p.load(vpp_config_filename)
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
                   dev         - PCI if device to apply labels to.
                   next_hop_ip - IP address of next hop.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """

    ids_list = fwglobals.g.router_api.multilink.get_label_ids_by_names(labels, remove)
    ids = ','.join(map(str, ids_list))

    if dev:
        vpp_if_name = pci_to_vpp_if_name(dev)
    elif sw_if_index:
        vpp_if_name = vpp_sw_if_index_to_name(sw_if_index)
    else:
        return (False, "Neither 'dev' nor 'sw_if_index' was found in params")

    if not next_hop:
        tap = vpp_if_name_to_tap(vpp_if_name)
        next_hop, _ = get_linux_interface_gateway(tap)
    if not next_hop:
        return (False, "'next_hop' was not provided and there is no default gateway")

    op = 'del' if remove else 'add'

    vppctl_cmd = 'fwabf link %s label %s via %s %s' % (op, ids, next_hop, vpp_if_name)

    fwglobals.log.debug("vppctl " + vppctl_cmd)

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

    if add:
        fwglobals.g.policies.add_policy(policy_id, priority)
    else:
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

    fwglobals.log.debug("vppctl " + vppctl_cmd)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None or 'unknown' in out:
        return (False, "failed vppctl_cmd=%s: %s" % (vppctl_cmd, out))

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

    fwglobals.log.debug("vppctl " + vppctl_cmd)

    out = _vppctl_read(vppctl_cmd, wait=False)
    if out is None:
        return (False, "failed vppctl_cmd=%s" % vppctl_cmd)

    return (True, None)

def get_interface_sw_if_index(ip):
    """Convert interface src IP address into gateway VPP sw_if_index.

    :param ip: IP address.

    :returns: sw_if_index.
    """

    pci, _ = fwglobals.g.router_cfg.get_wan_interface_gw(ip)
    return pci_to_vpp_sw_if_index(pci)

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

def get_interface_gateway(ip):
    """Convert interface src IP address into gateway IP address.

    :param ip: IP address.

    :returns: IP address.
    """

    pci, gw_ip = fwglobals.g.router_cfg.get_wan_interface_gw(ip)
    return ip_str_to_bytes(gw_ip)[0]

def get_reconfig_hash():
    res = ''
    wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')
    vpp_run = vpp_does_run()

    for wan in wan_list:
        name = None
        if 'pci' in wan and wan['pci'] != '':
            name = pci_to_linux_iface(wan['pci'])

            if name is None and vpp_run:
                name = pci_to_tap(wan['pci'])

        if name is None:
            return ''

        addr = get_interface_address(name)
        if not re.search(addr, wan['addr']):
            res += 'addr:' + addr + ','

        gw, metric = get_linux_interface_gateway(name)
        if not re.match(gw, wan['gateway']):
            res += 'gw:' + gw + ','

    if res:
        fwglobals.log.info('reconfig_hash_get: %s' % res)
        hash = hashlib.md5(res).hexdigest()
        return hash

    return ''

def add_static_route(addr, via, metric, remove, pci=None):
    """Add static route.

    :param params: params:
                        addr    - Destination network.
                        via     - Gateway address.
                        metric  - Metric.
                        remove  - True to remove route.
                        pci     - Device to be used for outgoing packets.

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
        if not pci:
            cmd = "sudo ip route %s %s%s nexthop via %s %s" % (op, addr, metric, via, next_hop)
        else:
            tap = pci_to_tap(pci)
            cmd = "sudo ip route %s %s%s nexthop via %s dev %s %s" % (op, addr, metric, via, tap, next_hop)

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True)
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

    fwglobals.log.debug("vppctl " + vppctl_cmd)

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
                'params' : { 'requests': msg }
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
                    'params' : params
                })

        return \
            {
                'message': 'aggregated',
                'params' : { 'requests': requests }
            }

    return msg  # No conversion is needed

def get_available_access_points(interface_name):
    """Get WIFI available access points.                            

    :param interface_name: Interface name to get.

    :returns: string array of essids
    """    
    #   -i wlxd0374523abfb
    access_points = []

    def clean(n): 
        n = n.replace('"', '')
        n = n.strip()
        n = n.split(':')[-1]
        return n

    # make sure the interface is up
    cmd = 'ip link set dev %s up' % interface_name
    subprocess.check_output(cmd, shell=True)
  
    try:
        cmd = 'iwlist %s scan | grep ESSID' % interface_name        
        access_points = subprocess.check_output(cmd, shell=True).splitlines()
        access_points = map(clean, access_points)         
        return access_points
    except subprocess.CalledProcessError:
        return access_points

def connect_to_wifi(params):
    interface_name = params['interfaceName']
    essid = params['essid']
    password = params['password']

    wpaIsRun = True if pid_of('wpa_supplicant') else False
    if (wpaIsRun):
        os.system('sudo killall wpa_supplicant')
        time.sleep(3)

    # create config file
    subprocess.check_output('wpa_passphrase %s %s | sudo tee /etc/wpa_supplicant.conf' % (essid, password), shell=True)

    try:
        output = subprocess.check_output('wpa_supplicant -i %s -c /etc/wpa_supplicant.conf -D wext -B -C /var/run/wpa_supplicant' % interface_name, shell=True)
        time.sleep(3)

        is_success = subprocess.check_output('wpa_cli  status | grep wpa_state | cut -d"=" -f2', shell=True)
        
        if (is_success.strip() == 'COMPLETED'):
            subprocess.check_output('dhclient %s' % interface_name, shell=True)
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False  

def is_lte_interface(interface_name):
    """Check if interface is LTE.                            

    :param interface_name: Interface name to check.

    :returns: Boolean.
    """
    interfaces = ['enp0s22u1u3i8', 'enp0s22u1u3i10']
    if interface_name in interfaces:
        return True
    
    return False

def connect_to_lte(params):
    interface_name = params['interfaceName']
    apn = params['apn']

    try:
        ser = serial.Serial('/dev/ttyUSB2', 115200, timeout=5)
        print(ser.name)        
        bye = ser.write("At!scact=1,1\r\n")     # write a string
        # time.sleep(3)
        response =  ser.read(2)

        # while True:
        #     response = ser.readline()
        #     print "python printed:", response


        ser.close()      
        # output = subprocess.check_output('wpa_supplicant -i %s -c /etc/wpa_supplicant.conf -D wext -B -C /var/run/wpa_supplicant' % interface_name, shell=True)
        # 

        # is_success = subprocess.check_output('wpa_cli  status | grep wpa_state | cut -d"=" -f2', shell=True)
        
        if (True):
            subprocess.check_output('dhclient %s' % interface_name, shell=True)
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False  

def is_wifi_interface(interface_name):
    """Check if interface is WIFI.                            

    :param interface_name: Interface name to check.

    :returns: Boolean.
    """    
    cmd = 'cat /proc/net/wireless | grep %s' % interface_name
    try:
        out = subprocess.check_output(cmd, shell=True).strip()
        return True
    except subprocess.CalledProcessError:
        return False   

def get_wifi_interface_driver(interface_name):
    """Get WIFI interface driver.                            

    :param interface_name: Interface name to check.

    :returns: driver name.
    """    
    #   -i wlxd0374523abfb
    try:
        cmd = 'ethtool -i %s' % interface_name        
        out = subprocess.check_output(cmd, shell=True).splitlines()
        vals = out[0].decode().split("driver: ", 1)
        return vals[-1]
    except subprocess.CalledProcessError:
        return ''   