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

class FwUnassignedIfs:
    """Class to monitor changes on none-assigned Linux interfaces.
    This class implements monitoring none-assigned Linux interfaces changes.
    None assigned interaces are interfaces that are not under the control of the VPP,
    and are not configured by FlexiManage, but pure Linux interfaces.
    If gets the full list of linux interfaces, and compare it with the list
    of interfaces in the router-db. Interfaces that are part of the router-db
    are not added to the cache of interfaces, as they are being monitored elsewhere.

    If a none-assigned interface becomes assigned, it will be added to the router-db.
    If it was part of the cache, it will be removed.
    If an assigned interface becomes unassigned, it will be removed from the router-db,
    hence added as a new interface to the cache.
    """

    def __init__(self):
        """ init function, initializing the cache for un-assigned interfaces.
        """
        fwglobals.g.AGENT_CACHE['linux_ifs'] = {}
        # Shorthand to the global cache
        self.cached_interfaces = fwglobals.g.AGENT_CACHE['linux_ifs']

    def _get_if_address(self, if_name):
        """ Get interface address.

        : param if_name : Interface name.
        : returns: string address on None
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

        return None

    def _get_assigned_interfaces(self):
        """ Get the list of assigned interfaces from the router-db. Those interfaces
        are already listed according to their PCI address, so we just add them to a
        list.

        : return : pci_list - list of PCI addresses for assigned interfaces
        """
        assigned_if = fwglobals.g.router_cfg.get_interfaces()
        if len(assigned_if) == 0:
            return []
        pci_list = [interface['pci'] for interface in assigned_if]
        return pci_list

    def _get_entry_fingerprint(self, pci):
        """ Computes a hash for an entry in the cache.

        : param pci : the PCI address which is the key in the cache dictionary
        : return : string of changes to calculate hash on.
        """
        res = ''
        vpp_run = fwutils.vpp_does_run()
        name    = fwutils.pci_to_linux_iface(pci)
        if name is None and vpp_run:
            name = fwutils.pci_to_tap(pci)
        if name is None:
            return res

        addr       = self._get_if_address(name)
        gw, metric = fwutils.get_linux_interface_gateway(name)

        if pci in self.cached_interfaces:
            entry = self.cached_interfaces[pci]
            # entry is in cache, check for differences between real-time info and cached info.
            # if the is a difference, add it to the computation, and update the cache.
            res += self._reconfig_section(entry,'addr',addr,only_if_different=True, update=True)
            res += self._reconfig_section(entry,'gateway',gw,only_if_different=True, update=True)
            res += self._reconfig_section(entry,'metric',metric,only_if_different=True, update=True)
            if gw and addr:
                # If GW exist, we need to check public info as well: compare local data
                # against STUN cache
                public_ip, public_port, _ = fwglobals.g.stun_wrapper.find_addr(addr)
                res += self._reconfig_section(entry,'public_ip',public_ip,only_if_different=True, update=True)
                res += self._reconfig_section(entry,'public_port',public_port,only_if_different=True, update=True)
        else:
            #entry is not in cache, create entry and update res
            self.cached_interfaces[pci] = {}
            entry = self.cached_interfaces[pci]
            entry['name'] = name

            res += self._reconfig_section(entry, 'addr', addr, only_if_different=False, update=True)
            res += self._reconfig_section(entry, 'gateway', gw, only_if_different=False, update=True)
            res += self._reconfig_section(entry, 'metric', metric, only_if_different=False, update=True)
            res += self._reconfig_section(entry, 'metric', metric, only_if_different=False, update=True)

            if gw and addr:
                public_ip, public_port, _ = fwglobals.g.stun_wrapper.find_addr(addr)
                res += self._reconfig_section(entry, 'public_ip', public_ip, only_if_different=False, update=True)
                res += self._reconfig_section(entry, 'public_port', public_port, only_if_different=False, update=True)
        return res

    def _reconfig_section(self, dct, key, value, only_if_different, update):
        """ compute reconfig diff when setting new value

        : param dct   : dictionary
        : param key   : dictionary's key
        : param value : dictionary's value
        : compare     : should compare before assignment
        : assignment  : should the dict be updated with new value
        : return : string of diff
        """
        res = ''
        if value:
            if only_if_different == True:
                if not re.match(value, dct.get(key)):
                    res = key + ':' + value + ','
            else:
                res = key + ':' + value + ','
        if update == True:
            dct[key] = value
        return res

    def _get_unassigned_reconfig_hash(self):
        """ Compute reconfig hash on interfaces in router-db.

        : return : string of changes in unassigned interfaces to calculate reconfig hash on
        """
        res = ''
        if_list = fwglobals.g.router_cfg.get_interfaces()
        if len(if_list) == 0:
            return res

        vpp_run = fwutils.vpp_does_run()
        for interface in if_list:
            name = fwutils.pci_to_linux_iface(interface.get('pci'))

            if name is None and vpp_run:
                name = fwutils.pci_to_tap(interface.get('pci'))

            if name is None:
                return ''

            addr = fwutils.get_interface_address(name)
            res += self._reconfig_section(interface, 'addr', addr, only_if_different=True, update=False)

            gw, metric = fwutils.get_linux_interface_gateway(name)
            res += self._reconfig_section(interface, 'gateway', gw, only_if_different=True, update=False)
            res += self._reconfig_section(interface, 'metric', metric, only_if_different=True, update=False)

            if addr and gw: # Don't bother sending STUN on LAN interfaces (which does not have gw)
                nomaskaddr = addr.split('/')[0]
                new_p_ip, new_p_port, _ = fwglobals.g.stun_wrapper.find_addr(nomaskaddr)
                addr_list = fwglobals.g.router_cfg.get_interface_public_addresses()
                for elem in addr_list:
                    if elem['address'] == nomaskaddr:
                        # compare public data between router-db and STUN cache
                        public_ip, public_port = elem['public_ip'], elem['public_port']
                        if public_ip:
                            if public_ip != new_p_ip:
                                  res += 'public_ip:' + new_p_ip + ','
                        if public_port:
                            if public_port != str(new_p_port):
                                res += 'public_port:' + str(new_p_port) + ','
                        break
        return res

    def get_reconfig_hash(self):
        """ This is the main function that updates the cache and computes the overall
        reconfig hash. It filters out the assigned interfaces from the linux interfaces,
        and updates each non-assigned interface with real-time changes made on the
        non-assigned linux devices.
        It then adds the reconfig hash of the assigned interfaces to the calculated hash
        from the cache, and run md5 on the result. This result is returned as the overall
        hahs of all the interfaces.

        : return : md5 hash result of all the changes.
        """
        res = ''

        linux_pci_list    = fwutils.get_linux_pcis()
        assigned_pci_list = self._get_assigned_interfaces()

        for pci in linux_pci_list:
            if pci in assigned_pci_list:
            # for assigned interfaces, reconfig is computed in fwutils.get_reconfig_hash()
                if pci in self.cached_interfaces:
                    # a case when unassigned interface became assigned. It will be
                    # computed in fwutils.get_reconfig_hash()
                    del self.cached_interfaces[pci]
            else:
                # the interface is unassigned, calculate hash. If this is a new interface
                # (or an interface that was assigned and became unassigned), it will be
                # added to the cache.
                res += self._get_entry_fingerprint(pci)

        # add the assigned-interfaces reconfig hash
        res += self._get_unassigned_reconfig_hash()

        if res != '':
            fwglobals.log.debug('get_reconfig_hash: %s' % res)
            hash = hashlib.md5(res).hexdigest()
            return hash
        else:
            return ''

    def is_unassigned_addr(self, address_no_mask):
        """ Check if an address is unassigned (part of cache)

        : param address_no_mask : address to look for, without mask
        : return: True if part of cache, False if not
        """
        for pci in self.cached_interfaces.keys():
            entry = self.cached_interfaces[pci]
            if address_no_mask == entry['addr'].split('/')[0]:
                return True
        return False

    def update_public(self, addr_no_mask, p_ip, p_port):
        """ Adds public information to entry in the unassigned hash.

        : param addr_no_mask : IP address without mask, to which to add the public info
        : param p_ip   : public IP to add to the entry
        : param p_port : public port to add to the entry
        """
        for pci in self.cached_interfaces.keys():
            entry = self.cached_interfaces[pci]
            if entry.get('addr'):
                if addr_no_mask == entry['addr'].split('/')[0]:
                    if entry.get('gateway'):
                        entry['public_ip'] = p_ip
                        entry['public_port'] = p_port
                        return

    def log_interfaces_cache(self):
        """ log cache into log
        """
        if self.cached_interfaces:
            for key in self.cached_interfaces.keys():
                entry = self.cached_interfaces[key]
                string = "FwUnassignedIfs: "
                string += entry.get('name','NoName') + ': {' + 'pci_address: ' + key + ', Address: '
                string += 'None' if entry.get('addr') == None else entry.get('addr')
                string += ', gateway: '
                string += 'None' if entry.get('gateway') == '' else entry.get('gateway','None')
                string += ', metric: '
                string += 'None' if entry.get('metric') == '' else entry.get('metric','None')
                if entry.get('gateway','') != '':
                    string += ', public_ip : '
                    string += 'None' if entry.get('public_ip') =='' else entry.get('public_ip', 'None')
                    string += ', public_port : '
                    string += 'None' if str(entry.get('public_port')) =='' else str(entry.get('public_port', 'None'))
                string += '}'
                fwglobals.log.debug(string)
