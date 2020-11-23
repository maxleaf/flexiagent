
import threading
import sys
import os
import re
import socket
import psutil
import fwglobals
import fwtunnel_stats
import fwutils
import time
import traceback
import copy
from sqlitedict import SqliteDict

tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools')
sys.path.append(tools)
import fwstun

class FwStunWrap:
    'Class to handle STUN requests and responses'
    """
    The router configuration file contains a list of interfaces that are
    added to the system. We go over the file and scan for "add-interface" keys.
    For that key, we look for its IP address and GW address. If the interface has
    both IP address and GW address, it means it can access the internet. If this
    is the case, we need to find out, if we're behind NAT, what is the public
    IP and port of that address.
    So we add them to a section on a global cache, and sends STUN request for
    each of the addresses. For those we get an answer, we mark a 'success' flag.
    For those we did not, we start resending STUN requests, with increased delay
    between each. We start with 1 sec, then 2, then 4, and ends with 60. Once
    we reach 60 seconds, we continue sending re-transmission of the requests
    every 60 seconds. Note, those counters are managed for each of the addresses
    separately.

    From globals, we use the global cache where following elements are kept:
    {
        'local_ip':
        'gateway':
        'public_ip':
        'public_port':
        'send_time':
        'success':
        'server_index':
        'nat_type':
    }

    Note that for unassigned WAN interfaces we would also like to get public info, to display in UI.
    In that case, the address will be part of the STUN cache, but also part of the unassigned cache.
    More info can be found in unassigned_if.py
    """

    def __init__(self, standalone):
        """ Init function. This function inits the cache, gets the router-db handle
            and register callback and request names to listen too.

            : param standalone : if set to TRUE, no traffic will be sent from the
                                 STUN module. We use this mode in pytest, for example.
                                 In pytests, we define bogus IP addresses, which we
                                 do not want to sent STUN requests on their behalf as
                                 they will produce nothing.
        """
        self.stun_cache    = fwglobals.g.cache.stun_cache
        self.thread_stun   = None
        self.is_running    = False
        self.standalone    = standalone
        self.stun_retry    = 60
        fwstun.set_log(fwglobals.log)

    def _log_address_cache(self):
        """ prints the content on the local cache
        """
        if self.stun_cache:
            for pci in self.stun_cache:
                # print only WAN address
                if self.stun_cache[pci].get('local_ip') != '' and \
                    self.stun_cache[pci].get('gateway') != '':
                    fwglobals.log.debug("FwStunWrap: " + pci + ':' + str(self.stun_cache[pci]))

    def initialize(self):
        """ Initialize STUN cache by sending STUN requests on all WAN interfaces before the first
        get-device-info is received. That way, the STUN cache will be ready with data when the
        system starts.
        After that, it starts the stun thread.
        """
        if self.standalone:
            return
        fwglobals.log.debug("Start sending STUN requests for all WAN interfaces")
        ifaces = fwutils.get_all_interfaces()
        if ifaces:
            ips = [ifaces[pci]['addr'] for pci in ifaces if ifaces[pci]['addr'] != '' \
                                and ifaces[pci]['gw'] != '']

            fwglobals.log.debug("stun_thread initialize: collected WAN IPs: %s" %(str(ips)))
            for pci in ifaces:
                self.add_addr(pci, ifaces[pci].get('addr'), ifaces[pci].get('gw'))
            self._send_stun_requests()
            self._log_address_cache()

        self.is_running = True
        fwglobals.log.debug("Starting STUN thread")
        if self.thread_stun is None:
            self.thread_stun = threading.Thread(target=self._stun_thread, name='STUN Thread')
            self.thread_stun.start()

    def finalize(self):
        """ Stop the STUN thread """
        self.is_running = False
        if self.thread_stun:
            self.thread_stun.join()
            self.thread_stun = None

    def _update_cache_from_OS(self):
        """ Check the OS to find newly added/removed WAN interfaces and add/remove them
        to/from the cache
        """
        tunnel_stats        = fwtunnel_stats.tunnel_stats_get()
        tunnels             = fwglobals.g.router_cfg.get_tunnels()
        tunnel_up_addr_list = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        os_pci_dict         = fwutils.get_all_interfaces()
        os_addr_list        = [os_pci_dict[pci].get('addr') for pci in os_pci_dict if os_pci_dict[pci].get('addr','') != '' \
                                    and os_pci_dict[pci].get('gw','') != '']
        cache_ip_list       = [self.stun_cache[pci].get('local_ip') for pci in self.stun_cache \
                                if self.stun_cache[pci].get('local_ip') != '' and self.stun_cache[pci].get('gateway') != '']

        fwglobals.log.debug("_update_cache_from_OS: WAN IP list from OS %s" %(str(os_addr_list)))
        fwglobals.log.debug("_update_cache_from_OS: WAN IP list from STUN cache %s" %(str(cache_ip_list)))

        # add updated IP from OS to Cache
        changed_flag = False
        for pci in os_pci_dict:
            if self.stun_cache.get(pci) and \
                os_pci_dict[pci].get('addr') == self.stun_cache[pci].get('local_ip') and \
                os_pci_dict[pci].get('gw') == self.stun_cache[pci].get('gateway'):
                continue
            else:
                # update STUN cache only if address is not part of connected tunnels. If the address
                # was updated in the OS, the tunnel will eventually get disconnected, and we will
                # deal with that later.
                addr = os_pci_dict[pci].get('addr')
                gw   = os_pci_dict[pci].get('gw')
                if addr not in tunnel_up_addr_list:
                    self.add_addr(pci, addr, gw)
                    changed_flag = True
        if changed_flag == True:
            self._log_address_cache()

    def add_addr(self, pci, addr, gateway):
        """ Add address to cache.

        : param pci     : PCI address of the interface
        : param addr    : Wan address to add to cache for STUN requests
        : param gateway : gateway of addr
        """
        if pci == None:
            # see if we can map the address to an existing PCI
            pci = self._map_ip_addr_to_pci(addr)
            if pci == None:
                fwglobals.log.debug("add_addr: no PCI was found for address %s, not updating cache" %(addr))
                return

        # Add an updated address to PCI entry in the cache.
        if pci not in self.stun_cache or self.stun_cache[pci].get('local_ip') != addr.split('/')[0] or \
                    self.stun_cache[pci].get('gateway') != gateway:
            cached_addr = self.initialize_addr(pci)
            cached_addr['local_ip']        = addr
            cached_addr['gateway']         = gateway
            cached_addr['server_index']     = 0
            cached_addr['nat_type']         = ''
            if addr:
                fwglobals.log.debug("Updating PCI address %s IP address %s in Cache" %(pci, addr))
            else:
                fwglobals.log.debug("Updating PCI address %s in Cache" %(pci))


    def find_addr(self,pci):
        """ find address in cache, and return its params, empty strings if not found

        : param pci : pci address to find in cache.
        : return :  local_ip associated with this PCI address -> str
                    public_ip of a local address or emptry string -> str
                    public_port of a local 4789 port or empty string -> int
                    nat_type which is the NAT server the device is behind or empty string -> str
        """
        if self.standalone:
            #return empty info
            return '', '', '', ''

        if pci in self.stun_cache:
            c = self.stun_cache[pci]
            return c.get('local_ip'), c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return '', '', '', ''

    def initialize_addr(self, pci):
        """ resets info for a PCI address, as if its local_ip never got a STUN reply.
        We will use it everytime we need to reset PCI's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for its local_ip. If the PCI address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out.

        : param pci : PCI address to reset in the cache.
        : return : the address entry in the cache -> dict
        """
        if pci in self.stun_cache:
            cached_addr = self.stun_cache[pci]
            cached_addr['local_ip']    = ''
            cached_addr['gateway']     = ''
            cached_addr['public_ip']   = ''
            cached_addr['public_port'] = ''
            cached_addr['send_time']   = 0
            cached_addr['success']     = False
        else:
            self.stun_cache[pci] = {
                                'local_ip':    '',
                                'gateway':     '',
                                'public_ip':   '',
                                'public_port': '',
                                'send_time'  : 0,
                                'success'    : False,
                                'server_index'    : 0,
                                'nat_type'        : '',
                           }

        return self.stun_cache[pci]

    def _reset_all(self):
        """ reset all data in the STUN cache for every interface that is not part
        of a connected tunnel. If the tunnel will get disconnected, it will add
        the address back to the STUN cache and reset it.
        """
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()
        tunnels      = fwglobals.g.router_cfg.get_tunnels()
        ip_up_set    = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        for (pci, cached_addr) in self.stun_cache.items():
            # Do not reset info on interface participating in a connected tunnel
            if cached_addr.get('local_ip') in ip_up_set:
                continue
            self.initialize_addr(pci)

    def _handle_stun_none_response(self, pci):
        """ Handle non response after STUN request was sent.
        continue to retry every self.stun_retry seconds.

        : param pci : the PCI address associated with an IP address for which we did not receive
                      STUN reply
        """
        cached_addr = self.stun_cache.get(pci)
        if not cached_addr:
            return
        cached_addr['send_time'] = time.time() + self.stun_retry # next retry after 60 seconds
        cached_addr['success'] = False
        cached_addr['server_index'] = 0
        fwglobals.log.debug("_handle_stun_none_response: failed getting public IP/port for address %s, retry in %d seconds"\
             %(cached_addr['local_ip'], self.stun_retry))

    def _handle_stun_response(self, pci, p_ip, p_port, nat_type, st_index):
        """ Handle STUN response for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.

        : param pci      : the PCI address associated with the address for which we received STUN reply
        : param p_ip     : the public IP received from STUN reply
        : param p_port   : the public port received from STUN reply
        : param nat_type : the NAT type of the NAT the STUN request was passed through
        : param st_index : The index of the STUN server in the list of servers from which a
                           good response was received
        """
        cached_addr = self.stun_cache.get(pci)
        if not cached_addr:
            return
        fwglobals.log.debug("found external %s:%s for %s:4789" %(p_ip, p_port, cached_addr['local_ip']))
        cached_addr['success']     = True
        cached_addr['send_time']   = 0
        cached_addr['nat_type']         = nat_type
        cached_addr['public_ip']        = p_ip
        cached_addr['public_port']      = p_port
        cached_addr['server_index']     = st_index

    def _send_stun_requests(self):
        """ Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the current time equals or greater than
        the calculated time it should be sent ('send_time').
        """
        if not self.stun_cache:
            return

        # now start sending STUN request
        for pci in self.stun_cache:
            cached_addr = self.stun_cache.get(pci)
            if not cached_addr or cached_addr.get('success',False) == True or cached_addr.get('gateway','') == '' \
                or self._is_useStun(pci) == False:
                continue

            if time.time() >= cached_addr['send_time']:
                local_ip = cached_addr['local_ip']
                nat_type, nat_ext_ip, nat_ext_port, server_index = \
                    self._send_single_stun_request(local_ip, 4789, cached_addr['server_index'])

                if nat_ext_port == '':
                    self._handle_stun_none_response(pci)
                else:
                    self._handle_stun_response(pci, nat_ext_ip, nat_ext_port,
                            nat_type, server_index)

    def _send_single_stun_request(self, lcl_src_ip, lcl_src_port, stun_idx):
        """ sends one STUN request for an address.

        : param lcl_src_ip   : local IP address
        : param lcl_srt_port : local port
        : param stun_idx     : The STUN index in the list of STUN from which STUN requests will
                               be sent from
        : return :  nat_type     - nat type of the NAT -> str
                    net_ext_ip   - the public IP address -> str
                    nat_ext_port - the public port -> int
                    stun_index   - the STUN server's index in the list of servers -> int
        """
        dev_name = fwutils.get_interface_name(lcl_src_ip)
        if dev_name == None:
            return '','','',''

        fwglobals.log.debug("trying to find external %s:%s for device %s" %(lcl_src_ip,lcl_src_port, dev_name))
        fwutils.set_linux_reverse_path_filter(dev_name, False)

        nat_type, nat_ext_ip, nat_ext_port, stun_index = \
            fwstun.get_ip_info(lcl_src_ip, lcl_src_port, None, None, dev_name, stun_idx)

        fwutils.set_linux_reverse_path_filter(dev_name, True)
        return nat_type, nat_ext_ip, nat_ext_port, stun_index

    def _stun_thread(self, *args):
        """STUN thread
        Its function is to send STUN requests for address:4789 in a timely manner
        according to some algorithm-based calculations.
        """
        slept = 1
        reset_all_timeout = 10 * 60
        update_cache_from_os_timeout = 2 * 60
        send_stun_timeout = 3
        log_stun_timeout = 2.5 * 60

        while self.is_running == True:

            try:  # Ensure thread doesn't exit on exception

                # Don't STUN if vpp is being initializing / shutting down,
                # as quering vpp for interface names/ip-s might generate exception.
                if not fwglobals.g.router_api.is_starting_stopping():

                    # send STUN requests for addresses that a request was not sent for
                    # them, or for ones that did not get reply previously
                    if slept % send_stun_timeout == 0:
                        self._send_stun_requests()

                    if slept % reset_all_timeout == 0:
                        # reset all STUN information every 10 minutes
                        self._reset_all()

                    if slept % update_cache_from_os_timeout == 0:
                        # every update_cache_timeout, refresh cache with updated IP addresses from OS
                        self._update_cache_from_OS()

                    if slept % log_stun_timeout == 0:
                        self._log_address_cache()

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

            time.sleep(1)
            slept += 1

    def handle_down_tunnels(self, tunnel_stats):
        """ Run over all tunnels and get the source IP address of the tunnels that are not connected.
        If it was disconnected due to changes in its source IP address, check if this IP address is still
        valid. If it is, check that it is not used in other connected tunnels. If it is not used but still
        valid, add it to the STUN cache. It it is in use, do not add it to the STUN cache, because we don't
        want to start sending STUN requests on its behalf as it will lead to disconnection of the other
        tunnels with that IP address.

        : param tunnel_stats : dictionary of tunnel statistics. One of its properties is the tunnel status
                            ("up" or "down")
        """
        if self.standalone:
            return

        tunnels = fwglobals.g.router_cfg.get_tunnels()

        if not tunnels:
            return

        # Get list if IP addresses used by tunnels
        ip_up_set = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        # Get list of all IP addresses in the system
        ifaces = fwutils.get_all_interfaces()
        ips = [ifaces[pci].get('addr') for pci in ifaces if ifaces[pci].get('addr') != '' \
            and ifaces[pci].get('gw') != '']
        for tunnel in tunnels:
            tunnel_id = tunnel['tunnel-id']
            stats = tunnel_stats.get(tunnel_id)
            if stats and stats.get('status') == 'down':
                # Down tunnel found. However, the tunnel might be disconnected due to changes in
                # source IP address. In that case, the current source address of the tunnel
                # is no longer valid. To make things safe, we check if the IP address exists
                # in the system. If it is not, no point on adding it to the STUN cache.
                if tunnel['src'] not in ips:
                    fwglobals.log.debug("Tunnel %d is down, but its source address %s was not found in the system"\
                        %(tunnel_id, tunnel['src']))
                    continue
                # If valid IP, check if the IP is part of other connected tunnels. If so,
                # do not add it to the STUN hash, as it might cause other connected tunnels
                # with that IP to disconnect. If it is not part of any connected tunnel,
                # updates its source IP address to the cache of addresses for which
                # we will send STUN requests.
                if tunnel['src'] not in ip_up_set:
                    fwglobals.log.debug("Tunnel %d is down, updating address %s in STUN interfaces cache"\
                        %(tunnel_id, tunnel['src']))
                    pci = self._get_tunnel_source_pci(tunnel_id)
                    # Force sending STUN request on behalf of the tunnel's source address
                    if self.stun_cache.get(pci):
                        self.stun_cache[pci]['success'] = False
                        # it takes around 30 seconds to create a tunnel, so don't
                        # start sending STUN requests right away
                        self.stun_cache[pci]['send_time'] = time.time() + 30

    def _is_useStun(self, pci):
        """ check router DB for 'useStun' flag for a PCI address
        : param pci : PCI address to check the flag for
        : return : 'useStun' value in DB, or False if not found -> Bool
        """
        interfaces = fwglobals.g.router_cfg.get_interfaces(pci=pci)
        if interfaces and interfaces[0].get('useStun') != '':
            return interfaces[0].get('useStun')

        # The PCI was not found in the DB, so it is an unassigned interface. Let's check
        # if it has a GW configured. It so, it is a WAN interface, and we will return 'True'
        vpp_run = fwutils.vpp_does_run()
        name = fwutils.pci_to_linux_iface(pci)
        if name is None and vpp_run:
            name = fwutils.pci_to_tap(pci)
        if not name:
            return False
        gw, _ = fwutils.get_interface_gateway(name)
        if not gw:
            return False
        return True

    def _get_tunnel_source_pci(self, tunnel_id):
        """ get the PCI address of the tunnel's source IP address
        : param tunnel_id : the ID of the tunnel for which we need the PCI for
        : return : PCI address, or None -> str
        """
        tunnel = fwglobals.g.router_cfg.get_tunnel(tunnel_id)
        if tunnel:
            return tunnel.get('pci')
        return None

    def _map_ip_addr_to_pci(self, ip_no_mask):
        """ Utility function to try and map existing IP address to PCI address.
        : param ip_no_mask : ip address without mask
        : return : PCI address or None -> str
        """
        pci_ip_dict = fwutils.get_all_interfaces()
        for pci in pci_ip_dict:
            if pci_ip_dict[pci].get('addr') == ip_no_mask:
                return pci
        return None