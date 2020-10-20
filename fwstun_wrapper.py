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
import copy

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
    fwglobals.g.AGENT_CACHE['stun_interfaces'][IP address] = {
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

    def log_address_cache(self):
        """ prints the content on the local cache
        """
        if self.local_cache['stun_interfaces']:
            for addr in self.local_cache['stun_interfaces'].keys():
                if addr:
                    fwglobals.log.debug("FwStunWrap: " + addr+':'+str(self.local_cache['stun_interfaces'][addr]))

    def __init__(self):
        """ Init function. This function inits the cache, gets the router-db handle
            and register callback and request names to listen too.
        """
        self.local_cache = fwglobals.g.AGENT_CACHE
        self.local_cache['stun_interfaces'] = {}
        self.thread_stun = None
        self.is_running = False
        fwglobals.g.router_cfg.register_callback('fwstunwrap', self.fwstuncb, \
            ['add-interface', 'remove-interface'])

    def initialize(self):
        """ Initialize STUN cache by sending STUN requests on all WAN interfaces before the first
        get-device-info is received. That way, the STUN cache will be ready with data when the
        system starts.
        After that, it starts the stun thread.
        """
        fwglobals.log.debug("Start sending STUN requests for all WAN interfaces")
        ip_list = fwutils.get_interfaces_ip_addr(filtr = 'gw')
        if ip_list:
            fwglobals.log.debug("stun_thread initialize: collected IPs: %s" %str(ip_list))
            for ip in ip_list:
                self._send_single_stun_request(ip, 4789, None, None, True)
            self.log_address_cache()

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
                self.add_addr(params['addr'].split('/')[0], False, params)
        else:
            # We know it is "remove" because we only registered for "add" and "remove"
            self.remove_addr(params['addr'].split('/')[0])

    def add_addr(self, addr, wait=False, params=None):
        """ Add address to cache.

        : param addr : Wan address to add to cache for STUN requests
        : param wait : passed to initialize_addr for counter setting. Can be True or False. See
                       initialize_addr() for more info
        : param params : parameters that can be received by management, or None
        """
        # 1 add address with public info, as received by add-address from management,
        # over-written the address if exist in cache.
        if params and params.get('PublicIP','') != '' and params.get('PublicPort','') != '' \
                and params.get('useStun', False) == True:
            cached_addr = self.initialize_addr(addr, wait)
            cached_addr['public_ip']        = params['PublicIP']
            cached_addr['public_port']      = params['PublicPort']
            cached_addr['success']          = True
            # if we are here, it is because agent sent the data previously to flexiManage.
            # In that case, the STUN server and port are already updated, no need to reset them.
            fwglobals.log.debug("adding address %s to Cache with public information" %(str(addr)))

        # 2 if address already in cache, do not add it, so its counters won't reset
        elif addr not in self.local_cache['stun_interfaces'].keys():
            cached_addr = self.initialize_addr(addr, wait)
            cached_addr['stun_server']      = ''
            cached_addr['stun_server_port'] = ''
            cached_addr['nat_type']         = ''
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))
        else:
        # 3 Address in cache but we still need its public data. Just make sure we are
        # continuing sending STUN request on that address
            self.local_cache['stun_interfaces'][addr]['success']          = False

    def remove_addr(self, addr):
        """ remove address from cache. The interface is no longer valid, no need to send
        STUN request on its behalf.
        Note that if the address is in the unassigned-interfaces cache, we will not
        remove it from current cache, as we still want to be able to get public IP:PORT
        on unassigned interfaces as well.

        : param addr : address to remove from cache.
        """
        if addr in self.local_cache['stun_interfaces'].keys():
            if fwglobals.g.unassigned_interfaces.is_unassigned_addr(addr) == False:
                del self.local_cache['stun_interfaces'][addr]
                fwglobals.log.debug("Removing address %s from Cache" %(str(addr)))
            else:
                fwglobals.log.debug("Address %s in unassigned cache, not removing" %(str(addr)))

    def find_addr(self,addr_no_mask):
        """ find address in cache, and return its params, empty strings if not found

        : param addr_no_mask : address to find in cache.
        : return :  public_ip of a local address or emptry string
                    public_port of a local 4789 port or empty string
                    nat_type which is the NAT server the device is behind or empty string
        """
        if addr_no_mask in self.local_cache['stun_interfaces'].keys():
            c = self.local_cache['stun_interfaces'][addr_no_mask]
            return c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return '', '', ''

    def initialize_addr(self, address, wait=False):
        """ resets info for an address, as if it never got a STUN reply.
        We will use it everytime we need to reset address's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for it. If the address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out. In that case,
        the underlying level will replace the STUN server in _send_single_stun_request().

        We initialize 'next_time' to 30, if we detect that tunnel is disconnected. The avarage time
        for tunnel to get connected from the time it was created is 30 seconds, so no point in sending
        STUN requests before, if the reason is public IP or Port were change. For the rest of the cases,
        we initialize 'next_time' to 1. See parameter 'wait' below.

        : param address :  address to reset in the cache.
        : param wait    :  If True, start 'next_time' counter from 30 (waiting for tunnel creation,
                           so no need to start sending STUN request when the tunnel is in the process
                           of connectring). False: start 'next_time' counter from 1.
        : return: the address entry in the cache
        """
        if address in self.local_cache['stun_interfaces'].keys():
            cached_addr = self.local_cache['stun_interfaces'][address]
            cached_addr['public_ip']   = ''
            cached_addr['public_port'] = ''
            cached_addr['sec_counter'] = 0
            cached_addr['success']     = False
        else:
            self.local_cache['stun_interfaces'][address] = {
                                'public_ip':  '',
                                'public_port':'',
                                'sec_counter':0,
                                'success':    False,
                                'stun_server': '',
                                'stun_server_port': '',
                                'nat_type'        : '',
                           }
        if wait == True:
            self.local_cache['stun_interfaces'][address]['next_time'] = 30
        else:
            self.local_cache['stun_interfaces'][address]['next_time'] = 1

        return self.local_cache['stun_interfaces'][address]

    def reset_all(self):
        """ reset all data in the STUN cache for every interface that is not part
        of a connected tunnel. If the tunnel will get disconnected, it will add
        the address back to the STUN cache and reset it.
        """
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        ip_up_set = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        for addr in self.local_cache['stun_interfaces']:
            # Do not reset info on interface participating in a connected tunnel
            if addr in ip_up_set:
                continue
            self.initialize_addr(addr, False)

    def _increase_sec(self):
        """ For each address not received an answer, increase the seconds counter by 1.
        """
        for addr in self.local_cache['stun_interfaces'].keys():
            address = self.local_cache['stun_interfaces'][addr]
            if address['success'] == False:
                address['sec_counter']+=1

    def _handle_stun_none_response(self, address):
        """ Handle non response after STUN request was sent.
        double the delay between retransmission, until reaching 60. Then
        continue with 60 until an answer will be received.

        : param address : the address for which we did not receive STUN reply
        """
        if self.local_cache['stun_interfaces'][address]['next_time'] < 60:
            self.local_cache['stun_interfaces'][address]['next_time']+=4
        if self.local_cache['stun_interfaces'][address]['next_time'] > 60:
            self.local_cache['stun_interfaces'][address]['next_time'] = 60
        self.local_cache['stun_interfaces'][address]['success'] = False

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
        fwglobals.log.debug("found external %s:%s for %s:4789" %(p_ip, p_port, address))
        cached_addr = self.local_cache['stun_interfaces'][address]
        cached_addr['success']     = True
        cached_addr['next_time']   = 1
        cached_addr['sec_counter'] = 0
        cached_addr['nat_type']         = nat_type
        cached_addr['public_ip']        = p_ip
        cached_addr['public_port']      = p_port
        cached_addr['stun_server']      = st_host
        cached_addr['stun_server_port'] = st_port

    def _send_stun_request(self):
        """ Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the seconds counter equals to
        the calculated time it should be sent ('next_time').
        """
        # Check if cache is empty. If it is, fill it with WAN addresses from router DB
        self.check_if_cache_empty()

        #now start sending STUN request
        for addr in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'].get(addr) and \
            self.local_cache['stun_interfaces'][addr]['success'] == True:
                continue
            else:
                elem = copy.deepcopy(self.local_cache['stun_interfaces'].get(addr))
                if elem == None:
                    continue
                if elem['sec_counter'] == elem['next_time']:
                    nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
                        self._send_single_stun_request(addr, 4789, elem['stun_server'], \
                        elem['stun_server_port'], False)
                    elem['sec_counter'] = 0
                    # address can be removed by another thread while iterating
                    if addr in self.local_cache['stun_interfaces'].keys():
                        self.local_cache['stun_interfaces'][addr] = copy.deepcopy(elem)
                    else:
                        continue

                    if nat_ext_port == '':
                        self._handle_stun_none_response(addr)
                    else:
                        self._handle_stun_response(addr, nat_ext_ip, nat_ext_port,\
                             nat_type, stun_host, stun_port)

    def check_if_cache_empty(self):
        """ If the agent and management are disconnected for some time,
        the cache can become empty (for example, if disconnection came after remove-interface).
        In that case, we will go to the router configuration, retreive interfaces with gateway,
        and fill the cache with those addresses.
        """
        if self.local_cache['stun_interfaces']:
            return
        fwglobals.log.debug("check_if_cache_empty: adding WAN addresses from Router-DB")
        addr_list = fwglobals.g.router_cfg.get_interface_public_addresses()
        ip_addr_list = fwutils.get_interfaces_ip_addr(filtr = 'gw')
        for elem in addr_list:
            # filter out left overs from previous unhandled router shut-down
            if elem['address'] in ip_addr_list:
                self.add_addr(elem['address'], False)
        return

    def _send_single_stun_request(self, lcl_src_ip, lcl_src_port, stun_addr, stun_port, try_once):
        """ sends one STUN request for an address.
        This function used in 2 cases:
        1. Send a single request when device is registering, and use the result to fill the cache.
        2. Send as part of STUN process from _send_stun_request(), that handles response and none-response
           cases.

        : param lcl_src_ip   : local IP address
        : param lcl_srt_port : local port
        : param stun_addr    : The STUN server address to send the request to
        : param stun_port    : The STUN server port to send the request to
        : param try_once     : if True, send only one request. We need this in case
                                of Register requests, and reconfig calculations.
                                If False, we update the cache based on the results
                                of the STUN reply, if any. This can lead to a new
                                entry in the cache.
        : return :  nat_type     - nat type of the NAT
                    net_ext_ip   - the public IP address
                    nat_ext_port - the public port
                    stun_host    - the STUN server the request was answered by
                    stun_port    - the STUN server's port
        """
        fwglobals.log.debug("trying to find external %s:%s" %(lcl_src_ip,lcl_src_port))
        nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
            fwstun.get_ip_info(lcl_src_ip, lcl_src_port, stun_addr, stun_port, try_once)

        if try_once == False:
            return nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port
        else:
            fwglobals.log.debug("_send_single_stun_request: adding address %s to cache" %(str(lcl_src_ip)))
            cached_addr = self.initialize_addr(lcl_src_ip, False)
            if nat_ext_ip != '' and nat_ext_port != '':
                fwglobals.log.debug("found external %s:%s for %s:%s" %(nat_ext_ip, nat_ext_port, lcl_src_ip,lcl_src_port))
                cached_addr['success']     = True
                cached_addr['nat_type']    = nat_type
                cached_addr['public_ip']   = nat_ext_ip
                cached_addr['public_port'] = nat_ext_port
                cached_addr['stun_server'] = stun_host
                cached_addr['stun_server_port'] = stun_port
                return None
            else:
                fwglobals.log.debug("failed to find external ip:port for %s:%d" %(lcl_src_ip,lcl_src_port))
                cached_addr['stun_server']      = ''
                cached_addr['stun_server_port'] = ''
                cached_addr['nat_type']  = nat_type if nat_type != '' else ''
                return None

    def _stun_thread(self, *args):
        """STUN thread
        Its function is to send STUN requests for address:4789 in a timely manner
        according to some algorithm-based calculations.
        """
        slept = 0
        timeout = 30
        reset_all_timeout = 10 * 60

        while self.is_running == True:
            # send STUN retquests for addresses that a request was not sent for
            # them, or for ones that did not get reply previously
            self._send_stun_request()
            self._increase_sec()

            if slept % (reset_all_timeout) == 0 and slept > 0:
                # reset all STUN information every 10 minutes, skip when slept is just initialized to 0
                self.reset_all()

            # dump STUN and unassigned interfaces information every 'timeout' seconds.
            # Wait 1 cycle so that the caches will be populated.
            if (slept % timeout) == 0 and slept > timeout:
                fwglobals.g.unassigned_interfaces.log_interfaces_cache()
                self.log_address_cache()
            time.sleep(1)
            slept += 1
