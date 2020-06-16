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

from netaddr import IPAddress
import psutil
import json
import fwutils
import fwstats
import os


# TBD: define all APIs in a file
os_modules = {
    'psutil':__import__('psutil'),
    'os':__import__('os'),
    'fwutils':__import__('fwutils'),
    'fwstats':__import__('fwstats')
}

# TBD: define all APIs in a file
os_api_defs = {
    'interfaces':{'module':'psutil', 'api':'net_if_addrs', 'decode':'interfaces'},
    'cpuutil':{'module':'psutil', 'api':'cpu_percent', 'decode':None},
    'exec':{'module':'os', 'api':'popen', 'decode':'execd'},
    'savefile':{'module':'fwutils', 'api':'save_file', 'decode':'default'},
    'pcisub':{'module':'fwutils', 'api':'pci_sub_file', 'decode':'default'},
    'tapsub':{'module':'fwutils', 'api':'tap_sub_file', 'decode':'default'},
    'gresub':{'module':'fwutils', 'api':'gre_sub_file', 'decode':'default'},
    'ifcount':{'module':'fwutils', 'api':'get_vpp_if_count', 'decode':'default'},
    'stop_router':{'module':'fwutils', 'api':'stop_router', 'decode':'default'},
    'connect_to_router':{'module':'fwutils', 'api':'connect_to_router', 'decode':None},
    'disconnect_from_router':{'module':'fwutils', 'api':'disconnect_from_router', 'decode':None}
}

class OS_DECODERS:
    """OS DECODERS class representation.
    """
    def interfaces(self, inp):
        """Get PCI address from Linux interface name for a list of interfaces.

        :param inp:         Interfaces.

        :returns: Array of interface descriptions.
        """
        out = []
        pciaddr = ''
        driver = ''
        vpp_run = fwutils.vpp_does_run()
        for nicname, addrs in inp.items():
            pci = fwutils.linux_to_pci_addr(nicname)
            if not vpp_run and pci[0] == "":
                continue
            if pci[0] != "":
                pciaddr = pci[0]
                driver = pci[1]
            daddr = {
                        'name':nicname,
                        'pciaddr':pciaddr,
                        'driver':driver,
                        'MAC':'',
                        'IPv4':'',
                        'IPv4Mask':'',
                        'IPv6':'',
                        'IPv6Mask':'',
                        'dhcp':'',
                        'gateway':''
                    }
            daddr['dhcp'] = fwutils.get_dhcp_netplan_interface(nicname)
            daddr['gateway'] = fwutils.get_gateway(nicname)
            for addr in addrs:
                addr_af_name = fwutils.af_to_name(addr.family)
                daddr[addr_af_name] = addr.address.split('%')[0]
                if addr.netmask != None:
                    daddr[addr_af_name + 'Mask'] = (str(IPAddress(addr.netmask).netmask_bits()))

                out.append(daddr)
        return (out,1)
    def execd(self, handle):
        """Read from a descriptor.

        :param handle:         File-like descriptor.

        :returns: Dta read from descriptor and status code.
        """
        data = handle.read()
        retcode = handle.close()
        if retcode == None or retcode == 0: ok=1
        else: ok=0
        return (data, ok)
    def default(self, inp):
        """Return default message.
        """
        return (inp['message'], inp['ok'])

class OS_API:
    """OS API class representation.
    """
    def __init__(self):
        """Constructor method
        """
        self.decoders = OS_DECODERS()

    def call_simple(self, req, params=None):
        """Handle a request from os_api_defs.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply with status and error message.
        """
        api_defs = os_api_defs.get(req)
        if api_defs == None:
            reply = {'entity':'osReply', 'message':'API Error', 'ok':0}
        else:
            module = os_modules.get(api_defs['module'])
            if module == None:
                reply = {'entity':'osReply', 'message':'API Error - Module error', 'ok':0}
            else:
                ok = 1
                if params and type(params)==dict:
                    result = getattr(module, api_defs['api'])(**params)
                elif params and type(params)==list:
                    result = getattr(module, api_defs['api'])(*params)
                else:
                    result = getattr(module, api_defs['api'])()

                if api_defs['decode'] != None:
                    (result, ok) = getattr(self.decoders, api_defs['decode'])(result)
                #print('OS API %s, Result: %s' % (req, str(result)))
                reply = {'entity':'osReply', 'message':result, 'ok':ok}
        return reply
