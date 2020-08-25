from sqlitedict import SqliteDict
import threading
import sys
import os
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

    def dump(self):
        """
        prints the content on the local cache
        """
        print ('stun_interfaces:')
        for addr in self.local_cache['stun_interfaces'].keys():
            if addr:
                print (addr+':'+str(self.local_cache['stun_interfaces'][addr]))

    def __init__(self):
        self.local_cache = fwglobals.g.AGENT_CACHE
        self.local_cache['stun_interfaces'] = {}
        self.local_db = SqliteDict(fwglobals.g.ROUTER_CFG_FILE, autocommit=True)
        self.run = True
        #self.is_running = True

    def initialize(self):
        fwglobals.g.router_cfg.register_request_callbacks('fwstunwrap', self.fwstuncb, \
            ['-add-interface', '-remove-interface'])

    def finalize(self):
        self.run = False

    def fwstuncb(request, params):
        """
        callback to be called from fwrouterCfg's update() function.
        """
        if re.match('-add-interface', request):
            if params['gateway'] is not '':
                self.add_addr(params[addr].split('/')[0])
        else:
            self.remove_addr(params[addr].split('/')[0])

    def add_addr(self, addr):
        """
        Add address to chace.
        """
        if addr not in self.local_cache['stun_interfaces'].keys():
            self.local_cache['stun_interfaces'][addr] = {
                'public_ip':None,
                'public_port':None,
                'sec_counter':0,
                'next_time':1,
                'success':False
            }

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
            return self.local_cache['stun_interfaces'][addr]
        else:
            return None

    def add_and_reset_addr(self, address):
        """
        resets info for an address, as if it never got a STUN reply.
        We will use it when we detect that a tunnel is dicsonnceted, and we
        need to start sending STUN request for it. If the address is already in the DB,
        we will reset its data.
        """
        self.local_cache['stun_interfaces'][address] = {
                            'public_ip':None,
                            'public_port':None,
                            'sec_counter':0,
                            'next_time':1,
                            'success':False
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

    def _handle_none_response(self, address):
        """
        Handle non response after STUN request was sent.
        double the delay between retransmission, until reaching 60. Then
        continue with 60 until an answer will be recieved.
        """
        addr = self.local_cache['stun_interfaces'][address]
        if addr['next_time'] < 60:
            addr['next_time']*=2
        if addr['next_time'] > 60:
            addr['next_time'] = 60
        addr['success'] = False

    def _handle_response(self, address, public_ip, public_port):
        """
        Handle STUN reposnse for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.
        """
        addr = self.local_cache['stun_interfaces'][address]
        addr['success'] = True
        addr['public_ip'] = public_ip
        addr['public_port'] = public_port
        addr['next_time'] = 1
        addr['sec_counter'] = 0

    def send_stun_request(self):
        """
        Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the seconds counter equels to
        the calculated time it should be sent ('next_time').
        """
        if self.run == False:
            return
        ext_ip = ext_port = None
        for key in self.local_cache['stun_interfaces'].keys():
            if self.local_cache['stun_interfaces'][key]['success'] == True:
                pass
            else:
                elem = self.local_cache['stun_interfaces'][key]
                addr = key
                if elem['sec_counter'] == elem['next_time']:
                    ext_ip, ext_port = self.find_srcip_public_addr(addr)
                    elem['sec_counter'] = 0
                    if ext_port == None:
                        self._handle_none_response(addr)
                    else:
                        self._handle_response(addr,ext_ip, ext_port)

    def find_srcip_public_addr(self, lcl_src_ip, lcl_src_port = 4789):
        """
        sends one STUN request for an address.
        """
        nat_type = None 
        nat_ext_ip = None 
        nat_ext_port = None
        fwglobals.log.debug("trying to find external %s:%s" %(lcl_src_ip,lcl_src_port))
        nat_type, nat_ext_ip, nat_ext_port = stun.get_ip_info(lcl_src_ip, lcl_src_port)
        if nat_ext_ip != None:
            fwglobals.log.debug("found external %s:%s for %s:%s" %(nat_ext_ip, nat_ext_port, lcl_src_ip,lcl_src_port))
            self.add_and_reset_addr(lcl_src_ip)
            self.local_cache['stun_interfaces'][lcl_src_ip]['success']     = True
            self.local_cache['stun_interfaces'][lcl_src_ip]['public_ip']   = nat_ext_ip
            self.local_cache['stun_interfaces'][lcl_src_ip]['public_port'] = nat_ext_port
            return nat_ext_ip, nat_ext_port
        else:
            fwglobals.log.debug("failed to find external ip:port for  %s:%s" %(lcl_src_ip,lcl_src_port))
            self.add_and_reset_addr(lcl_src_ip)
            return None,None

