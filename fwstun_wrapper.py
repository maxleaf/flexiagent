from sqlitedict import SqliteDict
import threading
import sys
import os
import re
import fwglobals

tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools')
sys.path.append(tools)
import stun

class FwStunWrap:
    'Class to handle STUN resuests and reposnses'
    """
    The router configuration file contains a list of interfaces that are
    added to the system. We go over the file and scan for "add-interface" keys.
    For that key, we look for its IP address and GW address. If the interface has
    both IP address and GW address, it means it can access the internet. If this
    is the case, we need to find out, if we're beinhd NAT, what is the public
    IP and port of that address.
    So we add them to a section on a gloval cache, and sends STUN request for
    each of the addresses. For those we get an asnwer, we mark a 'success' flag.
    For those we did not, we start resending STUN requests, with increased delay
    between each. We start with 1 sec, then 2, then 4, and ends with 60. Once
    we reach 60 seconds, we continue sending re-trasnission of the requests
    every 60 seconds. Note, those counters are managed for each of the addresses
    seperatly.  

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
    }
    """


    """
    if this will ever become a thread of its own, it is already ready

    def run(self):
        while self.is_running == True:
            time.sleep(1)
            #counter+=1
            self.increase_sec()
            self.send_stun_request()
    """

    def log_address_cache(self):
        """
        prints the content on the local cache
        """
        fwglobals.log.debug('stun_interfaces in Cache:')
        for addr in self.local_cache['stun_interfaces'].keys():
            if addr:
                fwglobals.log.debug(addr+':'+str(self.local_cache['stun_interfaces'][addr]))

    def __init__(self):
        self.local_cache = fwglobals.g.AGENT_CACHE
        self.local_cache['stun_interfaces'] = {}
        self.local_db = SqliteDict(fwglobals.g.ROUTER_CFG_FILE, autocommit=True)
        self.run = True
        fwglobals.g.router_cfg.register_request_callbacks('fwstunwrap', self.fwstuncb, \
            ['add-interface', 'remove-interface'])
        #self.is_running = True

    def fwstuncb(self, request, params):
        """
        callback to be called from fwrouterCfg's update() function.
        """
        if re.match('add-interface', request):
            if params['type'] == 'wan':
                self.add_addr(params['addr'].split('/')[0], params)
        else:
            # We know it is "remove" because we only registered for "add" and "remove"
            self.remove_addr(params['addr'].split('/')[0])

    def add_addr(self, addr, params=None):
        """
        Add address to chace. There are two cases here:
        1. The address already has public port and IP as part of its parameters,
        because this is how we got it from management, due to previous
        STUN requests (add-interface)
        2. The addres is new and has no public information.
        """
        c = self.local_cache['stun_interfaces']
        #1 add address with public info, over-written the address if exist in cache.
        if params and params['PublicIp'] and params['PublicPort']:
            self.reset_addr(addr)
            c[addr]['public_ip']        = params['PublicIp']
            c[addr]['public_port']      = params['PublicPort']
            c[addr]['sucess']           = True
            c[addr]['stun_server']      = None 
            c[addr]['stun_server_port'] = None
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))

        #2 if address already in cache, do not add it, so its counters won't reset
        elif addr not in self.local_cache['stun_interfaces'].keys():
            self.reset_addr(addr)
            c[addr]['stun_server']      = None 
            c[addr]['stun_server_port'] = None
            fwglobals.log.debug("adding address %s to Cache" %(str(addr)))
        else:
            fwglobals.log.debug("address %s already in Cache" %(str(addr)))

    def remove_addr(self, addr):
        """
        remove address from cache. The interface is no longer valid, no need to send 
        STUN request on its behalf.
        """
        if addr in self.local_cache['stun_interfaces'].keys():
            del self.local_cache['stun_interfaces'][addr]

    def find_addr(self,addr):
        """
        find address in cache, and return its params
        """
        if addr in self.local_cache['stun_interfaces'].keys():
            return self.local_cache['stun_interfaces'][addr]['public_ip'], \
                self.local_cache['stun_interfaces'][addr]['public_port']
        else:
            return None, None

    def reset_addr(self, address):
        """
        resets info for an address, as if it never got a STUN reply.
        We will use it everytime we need to reset address's data, such as in the case 
        when we detect that a tunnel is dicsonnceted, and we need to start sending STUN request
        for it. If the address is already in the cache, its values will be over-written.
        
        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out. In that case,
        the unerlying level will replace the STUN server in find_srcip_public_addr().

        we initialize 'next_time' to 30, because this is the everage time it take for
        a tunnel to get connected, so no point in sending STUN requests for disconnected tunnel
        before.
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
        For each address not recieved an answer, increase the seconds counter
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
        continue with 60 until an answer will be recieved.
        """
        addr = self.local_cache['stun_interfaces'][address]
        if addr['next_time'] < 60:
            addr['next_time']+=4
        if addr['next_time'] > 60:
            addr['next_time'] = 60
        addr['success'] = False

    def _handle_stun_response(self, address, public_ip, public_port):
        """
        Handle STUN reposnse for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.
        Some of the info was already updated by find_srcip_public_addr().
        """
        addr = self.local_cache['stun_interfaces'][address]
        addr['next_time']   = 30
        addr['sec_counter'] = 0
        addr['success']     = True
        addr['public_ip']   = public_ip
        addr['public_port'] = public_port

    def send_stun_request(self):
        """
        Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the seconds counter equels to
        the calculated time it should be sent ('next_time').
        """
        if self.run == False:
            return

        # Check if cache is empty. If it is, fill it with WAN addresses from router DB
        self.check_if_cache_empty()

        #now start sending STUN request
        ext_ip = ext_port = None
        for key in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'][key]['success'] == True:
                pass
            else:
                elem = self.local_cache['stun_interfaces'][key]
                addr = key
                if elem['sec_counter'] == elem['next_time']:
                    ext_ip, ext_port = self.find_srcip_public_addr(addr, 4789, elem['stun_server'], \
                        elem['stun_server_port'], False)
                    elem['sec_counter'] = 0
                    if ext_port == None:
                        self._handle_stun_none_response(addr)
                    else:
                        self._handle_stun_response(addr, ext_ip, ext_port)

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

    def find_srcip_public_addr(self, lcl_src_ip, lcl_src_port, stun_addr, stun_port, stop_after_one_try):
        """
        sends one STUN request for an address.
        This function used in 2 cases:
        1. Send a single request when device is registering, and use the result to fill the cache.
        2. Send as part of STUN process from send_stun_request(), that handles response and none-response
           cases.
        """
        nat_type = None 
        nat_ext_ip = None 
        nat_ext_port = None
        fwglobals.log.debug("trying to find external %s:%s" %(lcl_src_ip,lcl_src_port))
        nat_type, nat_ext_ip, nat_ext_port, stun_host, stun_port = \
            stun.get_ip_info(lcl_src_ip, lcl_src_port, stun_addr, stun_port, stop_after_one_try)

        fwglobals.log.debug("find_srcip_public_addr: adding address %s to cache" %(str(lcl_src_ip)))
        if nat_ext_ip and nat_ext_port:
            fwglobals.log.debug("found external %s:%s for %s:%s" %(nat_ext_ip, nat_ext_port, lcl_src_ip,lcl_src_port))
            self.reset_addr(lcl_src_ip)
            c = self.local_cache['stun_interfaces'][lcl_src_ip]
            c['success']     = True
            c['public_ip']   = nat_ext_ip
            c['public_port'] = nat_ext_port
            c['stun_server'] = stun_host
            c['stun_server_port'] = stun_port
            self.log_address_cache()
            return nat_ext_ip, nat_ext_port
        else:
            fwglobals.log.debug("failed to find external ip:port for  %s:%s" %(lcl_src_ip,lcl_src_port))
            self.reset_addr(lcl_src_ip)
            c = self.local_cache['stun_interfaces'][lcl_src_ip]
            c['stun_server']      = None
            c['stun_server_port'] = None
            return None,None

