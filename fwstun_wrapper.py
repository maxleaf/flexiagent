from sqlitedict import SqliteDict
import threading
import sys
import os
import re
import fwglobals

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

    get-device-info message reply collects information on all Linux interfaces. For that,
    it will send STUN requests on interfaces that might not be part of this cache, because
    user, using UI, choosed not to assign them to VPP. However, we do want to monitor
    information on unassigned interfaces, and display it in UI. Since reconfig will send
    STUN request on those interfaces, they will be added to this cache. The point is,
    interfaces will be added to the cache from number of reasons:
    1. After device registration, all interfaces with gateway will be added to the cache
    2. add-interface message from Fleximanage
    3. Call to reconfig on all interfaces, which might add new interfaces to the cache via
       calling send_single_stun_request()

    For more information, check fwunassigned_if.py file.
    """

    def log_address_cache(self):
        """
        prints the content on the local cache
        """
        if self.local_cache['stun_interfaces']:
            fwglobals.log.debug('stun_interfaces in Cache:')
            for addr in self.local_cache['stun_interfaces'].keys():
                if addr:
                    fwglobals.log.debug(addr+':'+str(self.local_cache['stun_interfaces'][addr]))

    def __init__(self):
        """ Init function. This function inits the cache, gets the router-db handle
            and register callback and request names to listen too.
        """
        self.local_cache = fwglobals.g.AGENT_CACHE
        self.local_cache['stun_interfaces'] = {}
        self.local_db = SqliteDict(fwglobals.g.ROUTER_CFG_FILE, autocommit=True)
        self.run = True
        fwglobals.g.router_cfg.register_callback('fwstunwrap', self.fwstuncb, \
            ['add-interface', 'remove-interface'])
        #self.is_running = True

    def fwstuncb(self, request, params):
        """
        callback to be called from fwrouterCfg's update() function.
        : param : request - the request to handle in the callback
        : param : params  - params for the request, if any.
        """
        if re.match('add-interface', request):
            if params['type'].lower() == 'wan':
                self.add_addr(params['addr'].split('/')[0], params)
        else:
            # We know it is "remove" because we only registered for "add" and "remove"
            self.remove_addr(params['addr'].split('/')[0])

    def add_addr(self, addr, params=None):
        """
        Add address to cache.
        : param : addr - Wan address to add to cache for STUN requests
        : param : params - parameters that can be received by management, or None
        """
        # 1 add address with public info, as received by add-address from management,
        # over-written the address if exist in cache.
        if params and 'PublicIp' in params and 'PublicPort' in params:
            self.reset_addr(addr)
            self.local_cache['stun_interfaces'][addr]['public_ip']        = params['PublicIp']
            self.local_cache['stun_interfaces'][addr]['public_port']      = params['PublicPort']
            self.local_cache['stun_interfaces'][addr]['success']          = True
            self.local_cache['stun_interfaces'][addr]['stun_server']      = None
            self.local_cache['stun_interfaces'][addr]['stun_server_port'] = None
            self.local_cache['stun_interfaces'][addr]['nat_type']         = None
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))

        # 2 if address already in cache, do not add it, so its counters won't reset
        elif addr not in self.local_cache['stun_interfaces'].keys():
            self.reset_addr(addr)
            self.local_cache['stun_interfaces'][addr]['stun_server']      = None
            self.local_cache['stun_interfaces'][addr]['stun_server_port'] = None
            self.local_cache['stun_interfaces'][addr]['nat_type']         = None
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))
        else:
        # 3 Address in cache but we still need its public data. Just make sure we are
        # continuing sending STUN request on that address
            self.local_cache['stun_interfaces'][addr]['success']          = False
            fwglobals.log.debug("address %s already in Cache" %(str(addr)))

    def remove_addr(self, addr):
        """
        remove address from cache. The interface is no longer valid, no need to send
        STUN request on its behalf.
        Note that if the address is in the unassigned-interfaces cache, we will not
        remove it from current cache, as we still want to be able to get public IP:PORT
        on unassigned interfaces as well.
        : param : addr - address to remove from cache.
        """
        if addr in self.local_cache['stun_interfaces'].keys():
            if fwglobals.g.unassigned_interfaces.is_unassigned_addr(addr) == False:
                del self.local_cache['stun_interfaces'][addr]
                fwglobals.log.debug("Removing address %s from Cache" %(str(addr)))
            else:
                fwglobals.log.debug("Address %s in unassigned cache, not removing" %(str(addr)))

    def find_addr(self,addr):
        """
        find address in cache, and return its params, or return None if address is not found
        : param : addr - address to find in cache.
        """
        if addr in self.local_cache['stun_interfaces'].keys():
            c = self.local_cache['stun_interfaces'][addr]
            return c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return None, None, None

    def reset_addr(self, address):
        """
        resets info for an address, as if it never got a STUN reply.
        We will use it everytime we need to reset address's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for it. If the address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out. In that case,
        the underlying level will replace the STUN server in send_single_stun_request().

        We initialize 'next_time' to 30, because this is the everage time it take for
        a tunnel to get connected, so no point in sending STUN requests for disconnected tunnel
        before.

        : param: address - address to reset in the cache.
        """
        self.local_cache['stun_interfaces'][address] = {
                            'public_ip':  None,
                            'public_port':None,
                            'sec_counter':0,
                            'next_time':  30,
                            'success':    False,
                            }

    def increase_sec(self):
        """
        For each address not received an answer, increase the seconds counter
        by 1.
        """
        for addr in self.local_cache['stun_interfaces'].keys():
            address = self.local_cache['stun_interfaces'][addr]
            if address['success'] == False:
                address['sec_counter']+=1

    def _handle_stun_none_response(self, address):
        """
        Handle non response after STUN request was sent.
        double the delay between retransmission, until reaching 60. Then
        continue with 60 until an answer will be received.
        : param : address - the address for which we did not receive STUN reply
        """
        if self.local_cache['stun_interfaces'][address]['next_time'] < 60:
            self.local_cache['stun_interfaces'][address]['next_time']+=4
        if self.local_cache['stun_interfaces'][address]['next_time'] > 60:
            self.local_cache['stun_interfaces'][address]['next_time'] = 60
        self.local_cache['stun_interfaces'][address]['success'] = False

    def _handle_stun_response(self, address, p_ip, p_port, nat_type, st_host, st_port):
        """
        Handle STUN response for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.
        : param : address  - the address for which we received STUN reply
        : param : p_ip     - the public IP received from STUN reply
        : param : p_port   - the public port received from STUN reply
        : param : nat_type - the NAT type of the NAT the STUN request was passed through
        : param : st_host  - The STUN server address
        : param : st_port  - The STUN server port
        """
        fwglobals.log.debug("found external %s:%s for %s:4789" %(p_ip, p_port, address))
        self.local_cache['stun_interfaces'][address]['success']     = True
        self.local_cache['stun_interfaces'][address]['next_time']   = 30
        self.local_cache['stun_interfaces'][address]['sec_counter'] = 0
        self.local_cache['stun_interfaces'][address]['nat_type']         = nat_type
        self.local_cache['stun_interfaces'][address]['public_ip']        = p_ip
        self.local_cache['stun_interfaces'][address]['public_port']      = p_port
        self.local_cache['stun_interfaces'][address]['stun_server']      = st_host
        self.local_cache['stun_interfaces'][address]['stun_server_port'] = st_port

    def send_stun_request(self):
        """
        Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the seconds counter equals to
        the calculated time it should be sent ('next_time').
        """
        if self.run == False:
            return

        # Check if cache is empty. If it is, fill it with WAN addresses from router DB
        self.check_if_cache_empty()

        #now start sending STUN request
        for addr in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'][addr]['success'] == True:
                pass
            else:
                elem = self.local_cache['stun_interfaces'][addr]
                if elem['sec_counter'] == elem['next_time']:
                    nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
                        self.send_single_stun_request(addr, 4789, elem['stun_server'], \
                        elem['stun_server_port'], False)
                    self.local_cache['stun_interfaces'][addr]['sec_counter'] = 0
                    if nat_ext_port == None:
                        self._handle_stun_none_response(addr)
                    else:
                        self._handle_stun_response(addr, nat_ext_ip, nat_ext_port,\
                             nat_type, stun_host, stun_port)

    def check_if_cache_empty(self):
        """
        If the agent and management are disconnected for some time,
        the cache can become empty. In that case, we will go to the router
        configuration, retreive interfaces with gateway, and fill the cache
        with those addresses.
        """
        if self.local_cache['stun_interfaces']:
            return
        for key in self.local_db.keys():
            if 'add-interface' in key:
                address = self.local_db[key]['params']['addr']
                if 'gateway' not in self.local_db[key]['params'] or  \
                   'gateway' in self.local_db[key]['params'] and \
                       self.local_db[key]['params']['gateway'] == '':
                    pass
                else:
                    address = address.split('/')[0]
                    self.add_addr(address)
        return

    def send_single_stun_request(self, lcl_src_ip, lcl_src_port, stun_addr, stun_port, try_once):
        """
        sends one STUN request for an address.
        This function used in 2 cases:
        1. Send a single request when device is registering, and use the result to fill the cache.
        2. Send as part of STUN process from send_stun_request(), that handles response and none-response
           cases.
        : param : lcl_src_ip     - local IP address
        : param : lcl_srt_port   - local port
        : param : stun_addr      - The STUN server address to send the request to
        : param : stun_port      - The STUN server port to send the request to
        : param : try_once       - if True, send only one request. We need this in case
                                   of Register requests, and reconfig calculations.
                                   If False, we update the cache based on the results
                                   of the STUN reply, if any. This can lead to a new
                                   entry in the cache.
        """
        fwglobals.log.debug("trying to find external %s:%s" %(lcl_src_ip,lcl_src_port))
        nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
            fwstun.get_ip_info(lcl_src_ip, lcl_src_port, stun_addr, stun_port, try_once)

        if try_once == False:
            return nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port
        else:
            fwglobals.log.debug("send_single_stun_request: adding address %s to cache" %(str(lcl_src_ip)))
            self.reset_addr(lcl_src_ip)
            if nat_ext_ip and nat_ext_port:
                fwglobals.log.debug("found external %s:%s for %s:%s" %(nat_ext_ip, nat_ext_port, lcl_src_ip,lcl_src_port))
                self.local_cache['stun_interfaces'][lcl_src_ip]['success']     = True
                self.local_cache['stun_interfaces'][lcl_src_ip]['nat_type']    = nat_type
                self.local_cache['stun_interfaces'][lcl_src_ip]['public_ip']   = nat_ext_ip
                self.local_cache['stun_interfaces'][lcl_src_ip]['public_port'] = nat_ext_port
                self.local_cache['stun_interfaces'][lcl_src_ip]['stun_server'] = stun_host
                self.local_cache['stun_interfaces'][lcl_src_ip]['stun_server_port'] = stun_port
                return
            else:
                fwglobals.log.debug("failed to find external ip:port for  %s:%d" %(lcl_src_ip,lcl_src_port))
                self.local_cache['stun_interfaces'][lcl_src_ip]['stun_server']      = None
                self.local_cache['stun_interfaces'][lcl_src_ip]['stun_server_port'] = None
                self.local_cache['stun_interfaces'][lcl_src_ip]['nat_type']         = None
                return

