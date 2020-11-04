from sqlitedict import SqliteDict
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
from random import seed, randint

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

    From globals, we use the global cache, and create fwglobals.g.AGENT_CACHE['stun_interfaces']
    sub dictionary. This dictionary has the following structure:
    fwglobals.g.AGENT_CACHE['stun_interfaces'][PCI address] = {
        'local_ip':
        'public_ip':
        'public_port':
        'sec_counter':
        'next_time':
        'success':
        'stun_server':
        'stun_server_port':
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
        self.local_cache = fwglobals.g.AGENT_CACHE
        self.local_cache['stun_interfaces'] = {}
        self.thread_stun = None
        self.is_running  = False
        self.standalone  = standalone
        if standalone:
            seed(1)
        fwglobals.g.router_cfg.register_callback('fwstunwrap', self.fwstuncb, \
            ['add-interface', 'remove-interface'])

    def _log_address_cache(self):
        """ prints the content on the local cache
        """
        if self.local_cache['stun_interfaces']:
            for pci in self.local_cache['stun_interfaces'].keys():
                fwglobals.log.debug("FwStunWrap: " + pci + ':' + str(self.local_cache['stun_interfaces'][pci]))

    def initialize(self):
        """ Initialize STUN cache by sending STUN requests on all WAN interfaces before the first
        get-device-info is received. That way, the STUN cache will be ready with data when the
        system starts.
        After that, it starts the stun thread.
        """
        fwglobals.log.debug("Start sending STUN requests for all WAN interfaces")
        pci_ip_dict = fwutils.get_interface_address_all(filtr = 'gw')
        if pci_ip_dict:
            ip_list = list(pci_ip_dict.values())
            fwglobals.log.debug("stun_thread initialize: collected IPs: %s" %(str(ip_list)))
            for pci, ip in pci_ip_dict.items():
                self.add_addr(pci, ip, False)
            if not self.standalone:
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

    def fwstuncb(self, request, params):
        """ allback to be called from fwrouterCfg's update() function.

        : param request : the request to handle in the callback
        : param params  : params for the request, if any.
        """
        if re.match('add-interface', request):
            if params['type'].lower() == 'wan':
                pci = request.split('add-interface:')[1]
                self.add_addr(pci, params['addr'].split('/')[0], False, params)
        else:
            # We know it is "remove" because we only registered for "add" and "remove"
            pci = request.split('remove-interface:')[0]
            self.remove_addr(pci, params['addr'].split('/')[0], params)

    def update_cache_from_OS(self):
        """ Check the OS to find newly added/removed WAN interfaces and add/remove them
        to/from the cache
        """
        tunnel_stats        = fwtunnel_stats.tunnel_stats_get()
        tunnels             = fwglobals.g.router_cfg.get_tunnels()
        tunnel_up_addr_list = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        os_addr_list        = fwutils.get_interface_address_all(filtr = 'gw')
        os_pci_list         = [interface[1] for interface in os_addr_list]
        cache_pci_list     = list(self.local_cache['stun_interfaces'].keys())
        chache_ip_list     = [self.local_cache['stun_interfaces'][pci].get('local_ip') for pci \
            in self.local_cache['stun_interfaces'].keys()]

        fwglobals.log.debug("update_cache_from_OS: WAN IP list from OS %s" %(str(os_addr_list)))
        fwglobals.log.debug("update_cache_from_OS: WAN IP list from STUN cache %s" %(str(cache_addr_list)))

        # add new IP from OS to Cache
        for ip in os_addr_list:
            if ip in cache_addr_list:
                continue
            else:
                fwglobals.log.debug("update_cache_from_OS: adding address %s" %(ip))
                self.add_addr(ip)

        # remove IPs from Cache if they are not part of OS IPs, unless they are part of connected
        # tunnels.
        # Since the IP does not exists, the tunnel will eventually get disconnected, and that
        # IP will not be added to the cache again. On the next call to this function, there
        # will be no associated connected tunnels with that IP address, and it will be removed.
        for ip in cache_addr_list:
            if ip not in os_addr_list and ip not in tunnel_up_addr_list:
                fwglobals.log.debug("update_cache_from_OS: removing address %s" %(ip))
                self.remove_addr(ip)

    def add_addr(self, pci, addr, wait=False, params=None):
        """ Add address to cache.

        : param pci  : PCI address of the interface
        : param addr : Wan address to add to cache for STUN requests
        : param wait : passed to initialize_addr for counter setting. Can be True or False. See
                       initialize_addr() for more info
        : param params : parameters that can be received by management, or None
        """
        if addr == '':
            return

        if pci == None:
            # see if we can map the address to an existing PCI
            pci_ip_dict = fwutils.get_interface_address_all(filtr = 'gw')
            for looked_pci, ip in pci_ip_dict.items():
                if pci_ip_dict[looked_pci] == addr:
                    pci = looked_pci
                    break
        if pci == None:
            fwglobals.log.debug("add_addr: no PCI was found for address %s, not adding to cache" %(addr))
            return

        if self.standalone:
            # add bogus info. More info can be found in the __init__ documentation.
            params = {}
            params['local_ip'] = addr
            params['PublicIP'] = "190.180.170.123"
            params['PublicPort'] = str(randint(1024,65535))
            params['useStun'] = True

        # 1 add address with public info, as received by add-address from management,
        # over-written the address if exist in cache.
        if params and params.get('PublicIP','') != '' and params.get('PublicPort','') != '' \
                and params.get('useStun', False) == True:
            cached_addr = self.initialize_addr(pci, wait)
            cached_addr['local_ip']    = addr.split('/')[0]
            cached_addr['public_ip']   = params['PublicIP']
            cached_addr['public_port'] = params['PublicPort']
            cached_addr['success']     = True
            # if we are here, it is because agent sent the data previously to flexiManage.
            # In that case, the STUN server and port are already updated, no need to reset them.
            fwglobals.log.debug("adding address %s to Cache with public information" %(str(addr)))

        # 2 if address already in cache, do not add it, so its counters won't be reset
        elif pci not in self.local_cache['stun_interfaces'].keys() or \
            (pci in self.local_cache['stun_interfaces'].keys() and \
                self.local_cache['stun_interfaces'][pci]['local_ip'] != addr.split('/')[0]):
            cached_addr = self.initialize_addr(pci, wait)
            cached_addr['local_ip']        = addr
            cached_addr['stun_server']      = ''
            cached_addr['stun_server_port'] = ''
            cached_addr['nat_type']         = ''
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))
        else:
        # 3 Address in cache but we still need its public data. Just make sure we are
        # continuing sending STUN request on that address
            self.local_cache['stun_interfaces'][pci]['success']          = False

    def remove_addr(self, pci, addr, params=None):
        """ remove address from cache. The interface is no longer valid, no need to send
        STUN request on its behalf.
        Note that if the address is in the unassigned-interfaces cache, we will not
        remove it from current cache, as we still want to be able to get public IP:PORT
        on unassigned interfaces as well.

        : param pci    : the PCI address of the interace
        : param addr   : address to remove from cache.
        : param params : interface parameters
        """
        if addr == '':
            return

        if pci in self.local_cache['stun_interfaces'].keys():
            if params and params.get('gateway','')!= '':
                    fwglobals.log.debug("remove_addr: pci %s: Address %s has gateway, not removing" %(pci, str(addr)))
            else:
                del self.local_cache['stun_interfaces'][pci]
                fwglobals.log.debug("remove_addr: pci %s: Removed address %s from Cache" %(pci, str(addr)))

    def find_addr(self,pci):
        """ find address in cache, and return its params, empty strings if not found

        : param pci : pci address to find in cache.
        : return :  local_ip associated with this PCI address
                    public_ip of a local address or emptry string
                    public_port of a local 4789 port or empty string
                    nat_type which is the NAT server the device is behind or empty string
        """
        if pci in self.local_cache['stun_interfaces'].keys():
            c = self.local_cache['stun_interfaces'][pci]
            return c.get('local_ip'), c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return '', '', '', ''

    def initialize_addr(self, pci, wait=False):
        """ resets info for a PCI address, as if its local_ip never got a STUN reply.
        We will use it everytime we need to reset PCI's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for its local_ip. If the PCI address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out.
        We initialize 'next_time' to 30, if we detect that tunnel is disconnected. The avarage time
        for tunnel to get connected from the time it was created is 30 seconds, so no point in sending
        STUN requests before, if the reason is public IP or Port were change. For the rest of the cases,
        we initialize 'next_time' to 0. See parameter 'wait' below.

        : param pci  :  PCI address to reset in the cache.
        : param wait :  If True, start 'next_time' counter from 30 (waiting for tunnel creation,
                        so no need to start sending STUN request when the tunnel is in the process
                        of connectring). False: start 'next_time' counter from 1.
        : return: the address entry in the cache
        """
        if pci in self.local_cache['stun_interfaces'].keys():
            cached_addr = self.local_cache['stun_interfaces'][pci]
            cached_addr['local_ip']    = ''
            cached_addr['public_ip']   = ''
            cached_addr['public_port'] = ''
            cached_addr['sec_counter'] = 0
            cached_addr['success']     = False
        else:
            self.local_cache['stun_interfaces'][pci] = {
                                'local_ip':   '',
                                'public_ip':  '',
                                'public_port':'',
                                'sec_counter':0,
                                'success':    False,
                                'stun_server': '',
                                'stun_server_port': '',
                                'nat_type'        : '',
                           }
        if wait == True:
            self.local_cache['stun_interfaces'][pci]['next_time'] = 30
        else:
            self.local_cache['stun_interfaces'][pci]['next_time'] = 0

        return self.local_cache['stun_interfaces'][pci]

    def reset_all(self):
        """ reset all data in the STUN cache for every interface that is not part
        of a connected tunnel. If the tunnel will get disconnected, it will add
        the address back to the STUN cache and reset it.
        """
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()
        tunnels      = fwglobals.g.router_cfg.get_tunnels()
        ip_up_set    = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        for pci in self.local_cache['stun_interfaces']:
            # Do not reset info on interface participating in a connected tunnel
            if self.local_cache['stun_interfaces'][pci]['local_ip'] in ip_up_set:
                continue
            self.initialize_addr(pci, False)

    def _increase_sec(self):
        """ For each address not received an answer, increase the seconds counter by 1.
        """
        for pci in self.local_cache['stun_interfaces'].keys():
            pci = self.local_cache['stun_interfaces'][pci]
            if pci['success'] == False:
                pci['sec_counter']+=1

    def _handle_stun_none_response(self, address):
        """ Handle non response after STUN request was sent.
        double the delay between retransmission, until reaching 60. Then
        continue with 60 until an answer will be received.

        : param address : the address for which we did not receive STUN reply
        """
        for pci in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'][pci]['local_ip'] == address:
                cached_addr = self.local_cache['stun_interfaces'][pci]
                if cached_addr['next_time'] < 60:
                    cached_addr['next_time'] += 4
                if cached_addr['next_time'] > 60:
                    cached_addr['next_time'] = 60
                cached_addr['success'] = False
                cached_addr['stun_server'] = ''
                cached_addr['stun_server_port'] = ''

    def _handle_stun_response(self, address, p_ip, p_port, nat_type, st_host, st_port):
        """ Handle STUN response for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.

        : param address  : the address for which we received STUN reply
        : param p_ip     : the public IP received from STUN reply
        : param p_port   : the public port received from STUN reply
        : param nat_type : the NAT type of the NAT the STUN request was passed through
        : param st_host  : The STUN server address
        : param st_port  : The STUN server port
        """
        for pci in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'][pci]['local_ip'] == address:
                fwglobals.log.debug("found external %s:%s for %s:4789" %(p_ip, p_port, address))
                cached_addr = self.local_cache['stun_interfaces'][pci]
                cached_addr['success']     = True
                cached_addr['next_time']   = 0
                cached_addr['sec_counter'] = 0
                cached_addr['nat_type']         = nat_type
                cached_addr['public_ip']        = p_ip
                cached_addr['public_port']      = p_port
                cached_addr['stun_server']      = st_host
                cached_addr['stun_server_port'] = st_port

    def _send_stun_requests(self):
        """ Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the seconds counter equals to
        the calculated time it should be sent ('next_time').
        """
        if not self.local_cache['stun_interfaces']:
            return

        if self.standalone:
            return

        # now start sending STUN request
        for pci in self.local_cache['stun_interfaces'].keys():
            elem = self.local_cache['stun_interfaces'].get(pci)
            if not elem or elem.get('success',False) == True:
                continue
            else:
                if elem['sec_counter'] >= elem['next_time']:
                    local_ip = elem['local_ip']
                    nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
                        self._send_single_stun_request(local_ip, 4789, elem['stun_server'], \
                        elem['stun_server_port'])
                    elem['sec_counter'] = 0
                    # address can be removed by another thread while iterating
                    if pci in self.local_cache['stun_interfaces'].keys():
                        self.local_cache['stun_interfaces'][pci] = copy.deepcopy(elem)
                    else:
                        continue

                    if nat_ext_port == '':
                        self._handle_stun_none_response(local_ip)
                    else:
                        self._handle_stun_response(local_ip, nat_ext_ip, nat_ext_port,\
                             nat_type, stun_host, stun_port)

    def _send_single_stun_request(self, lcl_src_ip, lcl_src_port, stun_addr, stun_port):
        """ sends one STUN request for an address.

        : param lcl_src_ip   : local IP address
        : param lcl_srt_port : local port
        : param stun_addr    : The STUN server address to send the request to
        : param stun_port    : The STUN server port to send the request to

        : return :  nat_type     - nat type of the NAT
                    net_ext_ip   - the public IP address
                    nat_ext_port - the public port
                    stun_host    - the STUN server the request was answered by
                    stun_port    - the STUN server's port
        """
        dev_name = fwutils.get_interface_name(lcl_src_ip)
        if dev_name == None:
            return '','','','',''

        fwglobals.log.debug("trying to find external %s:%s for device %s" %(lcl_src_ip,lcl_src_port, dev_name))
        fwutils.set_linux_reverse_path_filter(dev_name, False)

        nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
            fwstun.get_ip_info(lcl_src_ip, lcl_src_port, stun_addr, stun_port, dev_name)

        fwutils.set_linux_reverse_path_filter(dev_name, True)
        return nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port

    def _stun_thread(self, *args):
        """STUN thread
        Its function is to send STUN requests for address:4789 in a timely manner
        according to some algorithm-based calculations.
        """
        slept = 0
        timeout = 30
        reset_all_timeout = 10 * 60
        update_cache_from_os_timeout = 2 * 60

        while self.is_running == True:

            try:  # Ensure thread doesn't exit on exception

                # Don't STUN if vpp is being initializing / shutting down,
                # as quering vpp for interface names/ip-s might generate exception.
                if not fwglobals.g.router_api.is_starting_stopping():

                    # send STUN retquests for addresses that a request was not sent for
                    # them, or for ones that did not get reply previously
                    self._send_stun_requests()
                    self._increase_sec()

                    if slept % (reset_all_timeout) == 0 and slept > 0:
                        # reset all STUN information every 10 minutes, skip when slept is just initialized to 0
                        self.reset_all()

                    if slept % update_cache_from_os_timeout == 0 and slept > 0:
                        # every update_cache_timeout, refresh cache with updated IP addresses from OS
                        self.update_cache_from_OS()

                    # dump STUN information every 'timeout' seconds.
                    # Wait 1 cycle so that the cache will be populated.
                    if (slept % timeout) == 0 and slept > timeout:
                        self._log_address_cache()

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

            time.sleep(1)
            slept += 1

    def add_address_of_down_tunnels_to_stun(self, tunnel_stats, tunnels):
        """ Run over all tunnels and get the source IP address of the tunnels that are not connected.
        If it was disconnected due to changes in its source IP address, check if this IP address is still
        valid. If it is, check that it is not used in other connected tunnels. If it is not used but still
        valid, add it to the STUN cache. It it is in use, do not add it to the STUN cache, because we don't
        want to start sending STUN requests on its behalf as it will lead to disconnection of the other
        tunnels with that IP address.

        : param tunnel_stats : dictionary of tunnel statistics. One of its properties is the tunnel status
                            ("up" or "down")
        : param tunnels      : list of tunnels and their properties
        """
        if not tunnel_stats or not tunnels:
            return
        # Get list if IP addresses used by tunnels
        ip_up_set = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        # Get list of all IP addresses in the system
        pci_ip_list = fwutils.get_interface_address_all(filtr = 'gw')
        ip_list = [interface[1] for interface in pci_ip_list]
        for tunnel in tunnels:
            key = tunnel['tunnel-id']
            stats = tunnel_stats.get(key)
            if stats:
                status = stats.get('status')
                if status == 'down':
                    # Down tunnel found. However, the tunnel might be disconnected due to changes in
                    # source IP address. In that case, the current source address of the tunnel
                    # is no longer valid. To make things safe, we check if the IP address exists
                    # in the system. If it is not, no point on adding it to the STUN cache.
                    if tunnel['src'] not in ip_list:
                        fwglobals.log.debug("Tunnel-id %d is down, but its source address %s no longer valid"\
                            %(key, tunnel['src']))
                        continue
                    # If valid IP, check if the IP is part of other connected tunnels. If so,
                    # do not add it to the STUN hash, as it might cause other connected tunnels
                    # with that IP to disconnect. If it is not part of any connected tunnel,
                    # add its source IP address to the cache of addresses for which
                    # we will send STUN requests.
                    if tunnel['src'] not in ip_up_set:
                        fwglobals.log.debug("Tunnel-id %d is down, adding address %s to STUN interfaces cache"\
                            %(key, tunnel['src']))
                        self.add_addr(None, tunnel['src'], True)
                    continue
