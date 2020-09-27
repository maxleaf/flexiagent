################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020 flexiWAN Ltd.
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
import psutil
import fwglobals
import fwutils
import hashlib
import socket
import re
from netaddr import IPAddress

class FwLinuxIfs:
    'Class to monitor changes on none-assigned Linux interfaces'
    """
    This class implements monitoring none-assigned Linux interfaces changes.
    If gets the full list of linux interfaces, and compare it with the list
    of interfaces in the router-db. Interfaces that are part of the router-db
    are not added to the cache of interfaces, as they are being monitored elsewhere.

    If a none-assigned interface becomes assigned, it will be added to the router-db.
    If it was part of the cache, it will be removed.
    If an assigned interface becomes unassigned, it will be removed from the router-db,
    hence added as a new interface to the cache.
    """

    def __init__(self):
        """
        init function, initializing the cache for un-assigned interfaces.
        """
        fwglobals.g.AGENT_CACHE['linux_ifs'] = {}
        self.local_cache = fwglobals.g.AGENT_CACHE['linux_ifs']

    def _get_if_address(self, if_name):
        """Get interface address.
        :param : if_name - Interface name.
       :returns: address.
       """
        interfaces = psutil.net_if_addrs()
        if if_name not in interfaces:
            fwglobals.log.debug("_get_if_address(%s): interfaces: %s" % (if_name, str(interfaces)))
            return None

        addresses = interfaces[if_name]
        if len(addresses) > 1:
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    ip   = addr.address
                    mask = IPAddress(addr.netmask).netmask_bits()
                    return '%s/%s' % (ip, mask)
        elif len(addresses) == 1:
            return '%s' %(addresses[0].address)

        fwglobals.log.debug("_get_if_address(%s): %s" % (if_name, str(addresses)))
        return None

    def _get_linux_interfaces(self):
        """
        Get the list of all linux interfaces, according to their linux name.
        Then it convert the name to PCI address, and add them to a list.
        """
        pci_list = []
        interfaces = psutil.net_if_addrs()
        for nicname, addrs in interfaces.items():
            pciaddr = fwutils.linux_to_pci_addr(nicname)
            if pciaddr[0] == "":
                continue
            pci_list.append(pciaddr[0])
        return pci_list

    def _get_assigned_interfaces(self):
        """
        Get the list of assigned interfaces from the router-db. Those interfaces
        are already listed according to their PCI address, so we just add them to a
        list.
        """
        assigned_if = fwglobals.g.router_cfg.get_interfaces()
        if len(assigned_if) == 0:
            return []
        pci_list = [x['pci'] for x in assigned_if]
        return pci_list

    def _compute_entry_hash(self, pci_addr):
        """
        Computes a hash for an entry in the cache.
        : param : pci_addr - the PCI address which is the key in the cache dictionary
        """
        res = ''
        vpp_run = fwutils.vpp_does_run()
        name    = fwutils.pci_to_linux_iface(pci_addr)
        if name is None and vpp_run:
            name = fwutils.pci_to_tap(pci_addr)
        if name is None:
            return res

        addr       = self._get_if_address(name)
        gw, metric = fwutils.get_linux_interface_gateway(name)

        if pci_addr in self.local_cache:
            entry = self.local_cache[pci_addr]
            # entry is in cache, check for differences between real-time info and cached info.
            # if the is a difference, add it to the computation, and update the cache.
            if addr:
                if not re.search(addr, entry['addr']):
                    res += 'addr:' + addr + ','
            else:
                if entry.get('addr') and entry['addr'] != None:
                    res += 'addr:' + '' + ','
            entry['addr'] = addr

            if gw:
                if not re.match(gw, entry['gateway']):
                    res += 'gw:' + gw + ','
            else:
                if entry.get('gateway') and entry['gateway'] != '':
                    res += 'gateway:' + '' + ','
            entry['gateway'] = gw

            if metric:
                if not re.match(metric, entry['metric']):
                    res += 'metric:' + metric + ','
            else:
                if entry.get('metric') and entry['metric'] != '':
                    res += 'metric:' + '' + ','
            entry['metric'] = metric
        else:
            #entry is not in cache, create entry and update res
            self.local_cache[pci_addr] = {}
            entry = self.local_cache[pci_addr]
            entry['name'] = name

            if addr:
                res += 'addr:' + addr + ','
                entry['addr'] = addr
            else:
                res += 'addr:' + '' + ','
                entry['addr'] = None

            if gw:
                res += 'gw:' + gw + ','
                entry['gateway'] = gw
            else:
                res += 'gw:' + '' + ','
                entry['gateway'] = ''

            if metric:
                res += 'metric:' + metric + ','
                entry['metric'] = metric
            else:
                res += 'metric:' + '' + ','
                entry['metric'] = ''

        return res

    def get_global_reconfig_hash(self, update_public_info):
        """
        API
        This is the main function that updates the cache and computes the overall
        reconfig hash. It filters out the assigned interfaces from the linux interfaces,
        and updates each non-assigned interface with real-time changes made on the
        non-assigned linux devices.
        It then adds the reconfig hash of the assigned interfaces to the calculated hash
        from the cache, and run md5 on the result. This result is returned as the overall
        hahs of all the interfaces.
        : param : update_public_info - send to get_reconfig_hash, if True it will add
                 public IP and Port to the reconfig computation. This is to reduce STUN
                 requests.
        """
        res = ''
        linux_pci_list    = self._get_linux_interfaces()
        assigned_pci_list = self._get_assigned_interfaces()

        for pci_addr in linux_pci_list:
            if pci_addr in assigned_pci_list:
            # for assigned interfaces, reconfig is computed in fwutils.get_reconfig_hash()
                if pci_addr in self.local_cache:
                    # a case when unassigned interface became assigned. It will be
                    # computed in fwutils.get_reconfig_hash()
                    del self.local_cache[pci_addr]
            else:
                # the interface is unassigned, calculate hash. If this is a new interface
                # (or an interface that was assigned and became unassigned), it will be
                # added to the cache.
                res += self._compute_entry_hash(pci_addr)

        # add the assigned-interfaces reconfig hash
        res += fwutils.get_reconfig_hash(update_public_info)
        if res != '':
            fwglobals.log.debug('compute_global_reconfig_hash: %s' % res)
            hash = hashlib.md5(res).hexdigest()
            return hash

    def log_interfaces_cache(self):
        """
        log cache into log
        """
        if self.local_cache:
            fwglobals.log.debug('Unassigned interfaces in cache:')
            for key in self.local_cache.keys():
                entry = self.local_cache[key]
                string = entry['name'] + ': {' + 'pci_address: ' + key + ', Address: '
                string += 'None' if entry['addr'] == None else entry['addr']
                string += ', gateway: '
                string += 'None' if entry['gateway'] == '' else entry['gateway']
                string += ', metric: '
                string += 'None' if entry['metric'] == '' else entry['metric']
                string += '}'
                fwglobals.log.debug(string)
