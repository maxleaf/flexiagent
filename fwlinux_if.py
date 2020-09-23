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
import re

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

        gw, metric = fwutils.get_linux_interface_gateway(name)
        addr       = fwutils.get_interface_address(name)

        if pci_addr in self.local_cache:
            entry = self.local_cache[pci_addr]
            # entry is in cache, check for differences between real-time info and cached info.
            # if the is a difference, add it to the computation, and update the cache.
            if addr and not re.search(addr, pci_addr['addr']):
                res += 'addr:' + addr + ','
                entry['addr'] = addr

            if gw and not re.match(gw, pci_addr['gateway']):
                res += 'gw:' + gw + ','
                entry['gateway'] = gw

            if metric and not re.match(metric, pci_addr['metric']):
                res += 'metric:' + metric + ','
                entry['metric'] = metric
        else:
            #entry is not in cache, create entry and update res
            self.local_cache[pci_addr] = {}
            entry = self.local_cache[pci_addr]
            if addr:
                res += 'addr:' + addr + ','
                entry['addr'] = addr

            if gw:
                res += 'gw:' + gw + ','
                entry['gateway'] = gw

            if metric:
                res += 'metric:' + metric + ','
                entry['metric'] = metric

        return res

    def get_global_reconfig_hash(self):
        """
        API
        This is the main function that updates the cache and computes the overall
        reconfig hash. It filters out the assigned interfaces from the linux interfaces,
        and updates each non-assigned interface with real-time changes made on the 
        non-assigned linux devices.
        It then adds the reconfig hash of the assigned interfaces to the calculated hash
        from the cache, and run md5 on the result. This result is returned as the overall
        hahs of all the interfaces.
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
        res += fwutils.get_reconfig_hash()
        if res != '':
            fwglobals.log.info('compute_global_reconfig_hash: %s' % res)
            hash = hashlib.md5(res).hexdigest()
            return hash
