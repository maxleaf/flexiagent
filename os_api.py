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
import fwnetplan
import fwutils
import fwstats
import os
import fwglobals

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
    'ifcount':{'module':'fwutils', 'api':'get_vpp_if_count', 'decode':'default'},
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
        for nicname, addrs in inp.items():
            pciaddr = fwutils.linux_to_pci_addr(nicname)
            if pciaddr and pciaddr[0] == "":
                continue
            daddr = {
                        'name':nicname,
                        'pciaddr':pciaddr[0],
                        'driver':pciaddr[1],
                        'MAC':'',
                        'IPv4':'',
                        'IPv4Mask':'',
                        'IPv6':'',
                        'IPv6Mask':'',
                        'dhcp':'',
                        'gateway':'',
                        'metric': '',
                    }
            daddr['dhcp'] = fwnetplan.get_dhcp_netplan_interface(nicname)
            daddr['gateway'], daddr['metric'] = fwutils.get_linux_interface_gateway(nicname)
            for addr in addrs:
                addr_af_name = fwutils.af_to_name(addr.family)
                daddr[addr_af_name] = addr.address.split('%')[0]
                if addr.netmask != None:
                    daddr[addr_af_name + 'Mask'] = (str(IPAddress(addr.netmask).netmask_bits()))

            if daddr['gateway'] is not '':
                # Find Public port and IP for the address. At that point
                # the STUN interfaces cache should be already initialized.
                daddr['public_ip'], daddr['public_port'], daddr['nat_type'] = \
                    fwglobals.g.stun_wrapper.find_addr(daddr['IPv4'])

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

    def call_simple(self, request):
        """Handle a request from os_api_defs.

        :param request: The request received from flexiManage.

        :returns: Reply with status and error message.
        """
        req    = request['message']
        params = request.get('params')

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
