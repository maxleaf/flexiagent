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
        self.sym_nat_cache = fwglobals.g.cache.sym_nat_cache
        self.sym_nat_tunnels_cache = fwglobals.g.cache.sym_nat_tunnels_cache
        self.thread_stun   = None
        self.standalone    = standalone
        self.stun_retry    = 60
        fwstun.set_log(fwglobals.log)

    def _log_address_cache(self):
        """ prints the content on the local cache
        """
        if self.stun_cache:
            for dev_id in self.stun_cache:
                # print only WAN address
                if self.stun_cache[dev_id].get('local_ip') != '' and \
                    self.stun_cache[dev_id].get('gateway') != '':
                    fwglobals.log.debug(dev_id + ':' + str(self.stun_cache[dev_id]))

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
            ips = [ifaces[dev_id]['addr'] for dev_id in ifaces if ifaces[dev_id]['addr'] != '' \
                                and ifaces[dev_id]['gw'] != '']

            fwglobals.log.debug("stun_thread initialize: collected WAN IPs: %s" %(str(ips)))
            for dev_id in ifaces:
                self.add_addr(dev_id, ifaces[dev_id].get('addr'), ifaces[dev_id].get('gw'))
            self._send_stun_requests()
            self._log_address_cache()

        self.thread_stun = threading.Thread(target=self._stun_thread, name='STUN Thread')
        self.thread_stun.start()

    def finalize(self):
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
        os_dev_id_dict         = fwutils.get_all_interfaces()
        os_addr_list        = [os_dev_id_dict[dev_id].get('addr') for dev_id in os_dev_id_dict if os_dev_id_dict[dev_id].get('addr','') != '' \
                                    and os_dev_id_dict[dev_id].get('gw','') != '']
        cache_ip_list       = [self.stun_cache[dev_id].get('local_ip') for dev_id in self.stun_cache \
                                if self.stun_cache[dev_id].get('local_ip') != '' and self.stun_cache[dev_id].get('gateway') != '']

        fwglobals.log.debug("_update_cache_from_OS: WAN IP list from OS %s" %(str(os_addr_list)))
        fwglobals.log.debug("_update_cache_from_OS: WAN IP list from STUN cache %s" %(str(cache_ip_list)))

        # add updated IP from OS to Cache
        changed_flag = False
        for dev_id in os_dev_id_dict:
            if self.stun_cache.get(dev_id) and \
                os_dev_id_dict[dev_id].get('addr') == self.stun_cache[dev_id].get('local_ip') and \
                os_dev_id_dict[dev_id].get('gw') == self.stun_cache[dev_id].get('gateway'):
                continue
            else:
                # update STUN cache only if address is not part of connected tunnels. If the address
                # was updated in the OS, the tunnel will eventually get disconnected, and we will
                # deal with that later.
                addr = os_dev_id_dict[dev_id].get('addr')
                gw   = os_dev_id_dict[dev_id].get('gw')
                if addr not in tunnel_up_addr_list:
                    self.add_addr(dev_id, addr, gw)
                    changed_flag = True
        if changed_flag == True:
            self._log_address_cache()

    def add_addr(self, dev_id, addr, gateway):
        """ Add address to cache.

        : param dev_id  : Bus address of the interface
        : param addr    : Wan address to add to cache for STUN requests
        : param gateway : gateway of addr
        """
        if dev_id == None:
            # see if we can map the address to an existing dev id
            dev_id = self._map_ip_addr_to_dev_id(addr)
            if dev_id == None:
                fwglobals.log.debug("add_addr: no dev_id was found for address %s, not updating cache" %(addr))
                return

        # Add an updated address to dev id entry in the cache.
        if dev_id not in self.stun_cache or self.stun_cache[dev_id].get('local_ip') != addr.split('/')[0] or \
                    self.stun_cache[dev_id].get('gateway') != gateway:
            cached_addr = self.initialize_addr(dev_id)
            cached_addr['local_ip']        = addr
            cached_addr['gateway']         = gateway
            cached_addr['server_index']     = 0
            cached_addr['nat_type']         = ''
            if addr:
                fwglobals.log.debug("Updating dev_id address %s IP address %s in Cache" %(dev_id, addr))
            else:
                fwglobals.log.debug("Updating dev_id address %s in Cache" %(dev_id))


    def find_addr(self, dev_id):
        """ find address in cache, and return its params, empty strings if not found

        : param dev_id : interface bus address to find in cache.
        : return :  local_ip associated with this dev id address -> str
                    public_ip of a local address or emptry string -> str
                    public_port of a local 4789 port or empty string -> int
                    nat_type which is the NAT server the device is behind or empty string -> str
        """
        if self.standalone:
            #return empty info
            return '', '', ''

        if dev_id in self.stun_cache:
            c = self.stun_cache[dev_id]
            return c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return '', '', ''

    def initialize_addr(self, dev_id):
        """ resets info for a dev id address, as if its local_ip never got a STUN reply.
        We will use it everytime we need to reset dev id's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for its local_ip. If the dev id address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out.

        : param dev_id : Bus address to reset in the cache.
        : return : the address entry in the cache -> dict
        """
        if dev_id in self.stun_cache:
            cached_addr = self.stun_cache[dev_id]
            cached_addr['local_ip']    = ''
            cached_addr['gateway']     = ''
            cached_addr['public_ip']   = ''
            cached_addr['public_port'] = ''
            cached_addr['send_time']   = 0
            cached_addr['success']     = False
        else:
            self.stun_cache[dev_id] = {
                                'local_ip':    '',
                                'gateway':     '',
                                'public_ip':   '',
                                'public_port': '',
                                'send_time'  : 0,
                                'success'    : False,
                                'server_index'    : 0,
                                'nat_type'        : '',
                           }

        fwutils.set_linux_interfaces_stun(dev_id, '', '', '')

        return self.stun_cache[dev_id]

    def _reset_all(self):
        """ reset all data in the STUN cache for every interface that is not part
        of a connected tunnel. If the tunnel will get disconnected, it will add
        the address back to the STUN cache and reset it.
        """
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()
        tunnels      = fwglobals.g.router_cfg.get_tunnels()
        ip_up_set    = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        for (dev_id, cached_addr) in list(self.stun_cache.items()):
            # Do not reset info on interface participating in a connected tunnel
            if cached_addr.get('local_ip') in ip_up_set:
                continue
            self.initialize_addr(dev_id)

    def _handle_stun_none_response(self, dev_id):
        """ Handle non response after STUN request was sent.
        continue to retry every self.stun_retry seconds.

        : param dev_id : the Bus address associated with an IP address for which we did not receive
                      STUN reply
        """
        cached_addr = self.stun_cache.get(dev_id)
        if not cached_addr:
            return
        cached_addr['send_time'] = time.time() + self.stun_retry # next retry after 60 seconds
        cached_addr['success'] = False
        cached_addr['server_index'] = 0
        fwglobals.log.debug("_handle_stun_none_response: failed getting public IP/port for address %s, retry in %d seconds"\
             %(cached_addr['local_ip'], self.stun_retry))

    def _handle_stun_response(self, dev_id, p_ip, p_port, nat_type, st_index):
        """ Handle STUN response for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.

        : param dev_id   : the bus address associated with the address for which we received STUN reply
        : param p_ip     : the public IP received from STUN reply
        : param p_port   : the public port received from STUN reply
        : param nat_type : the NAT type of the NAT the STUN request was passed through
        : param st_index : The index of the STUN server in the list of servers from which a
                           good response was received
        """
        cached_addr = self.stun_cache.get(dev_id)
        if not cached_addr:
            return
        fwglobals.log.debug("found external %s:%s for %s:4789" %(p_ip, p_port, cached_addr['local_ip']))
        cached_addr['success']     = True
        cached_addr['send_time']   = 0
        cached_addr['nat_type']         = nat_type
        cached_addr['public_ip']        = p_ip
        cached_addr['public_port']      = p_port
        cached_addr['server_index']     = st_index

        fwutils.set_linux_interfaces_stun(dev_id, p_ip, p_port, nat_type)

    def _send_stun_requests(self):
        """ Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the current time equals or greater than
        the calculated time it should be sent ('send_time').
        """
        if not self.stun_cache:
            return

        # now start sending STUN request
        for dev_id in self.stun_cache:
            cached_addr = self.stun_cache.get(dev_id)
            if not cached_addr or cached_addr.get('success',False) == True or cached_addr.get('gateway','') == '' \
                or self._is_useStun(dev_id) == False:
                continue

            if time.time() >= cached_addr['send_time']:
                local_ip = cached_addr['local_ip']
                nat_type, nat_ext_ip, nat_ext_port, server_index = \
                    self._send_single_stun_request(local_ip, 4789, cached_addr['server_index'])

                if nat_ext_port == '':
                    self._handle_stun_none_response(dev_id)
                else:
                    self._handle_stun_response(dev_id, nat_ext_ip, nat_ext_port,
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

        nat_type, nat_ext_ip, nat_ext_port, stun_index = \
            fwstun.get_ip_info(lcl_src_ip, lcl_src_port, None, None, dev_name, stun_idx)

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
        probe_sym_nat_timeout = 30
        send_sym_nat_timeout = 3

        while not fwglobals.g.teardown:

            try:  # Ensure thread doesn't exit on exception

                # Don't STUN if vpp is being initializing / shutting down,
                # as quering vpp for interface names/ip-s might generate exception.
                if not fwglobals.g.router_api.state_is_starting_stopping():

                    # send STUN requests for addresses that a request was not sent for
                    # them, or for ones that did not get reply previously
                    if slept % send_stun_timeout == 0:
                        self._send_stun_requests()

                    # probe tunnels in down state to see if we could find remote edge
                    # address/port from incoming packets for symmetric NAT traversal

                    if slept % send_sym_nat_timeout == 0:
                        self._send_symmetric_nat()

                    if slept % probe_sym_nat_timeout == 0:
                        self._probe_symmetric_nat()

                    if slept % reset_all_timeout == 0:
                        # reset all STUN information every 10 minutes
                        self._reset_all()

                    if slept % update_cache_from_os_timeout == 0:
                        # every update_cache_timeout, refresh cache with updated IP addresses from OS
                        self._update_cache_from_OS()

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

        self.sym_nat_tunnels_cache.clear()

        tunnels = fwglobals.g.router_cfg.get_tunnels()

        if not tunnels:
            return

        # Get list if IP addresses used by tunnels
        ip_up_set = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        # Get list of all IP addresses in the system
        ifaces = fwutils.get_all_interfaces()
        ips = [ifaces[dev_id].get('addr') for dev_id in ifaces if ifaces[dev_id].get('addr') != '' \
            and ifaces[dev_id].get('gw') != '']
        for tunnel in tunnels:
            tunnel_id = tunnel['tunnel-id']
            dev_id = self._get_tunnel_source_dev_id(tunnel_id)
            stats = tunnel_stats.get(tunnel_id)

            # If tunnel is UP, skip it while clearing the cache
            if not stats or stats.get('status') != 'down':
                if self.stun_cache.get(dev_id):
                    self.stun_cache[dev_id]['success'] = True
                    self.stun_cache[dev_id]['send_time'] = 0
                if self.sym_nat_cache.get(dev_id):
                    self.sym_nat_cache['probe_time'] = 0
                continue

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
                # Force sending STUN request on behalf of the tunnel's source address
                if self.stun_cache.get(dev_id):
                    self.stun_cache[dev_id]['success'] = False
                    # it takes around 30 seconds to create a tunnel, so don't
                    # start sending STUN requests right away
                    self.stun_cache[dev_id]['send_time'] = time.time() + 30

            # Assume that remote edge is behind symmetric NAT
            # Try to discover remote edge ip and port from incoming packets.
            if self.sym_nat_cache.get(dev_id):
                if self.sym_nat_cache[dev_id]['probe_time'] == 0:
                    fwglobals.log.debug("Re-try to discover remote edge for tunnel: %d on dev %s"%(tunnel_id, dev_id))
                    self.sym_nat_cache[dev_id]['local_ip'] = tunnel['src']
                    self.sym_nat_cache[dev_id]['probe_time'] = time.time() + 25
            elif dev_id is not None:
                fwglobals.log.debug("Try to discover remote edge for tunnel %d on dev %s"%(tunnel_id, dev_id))
                self.sym_nat_cache[dev_id] = {
                            'local_ip'    : tunnel['src'],
                            'probe_time'  : time.time() + 25,
                        }
            else:
                fwglobals.log.debug("Dev is %s for tunnel %d"%(dev_id, tunnel_id))

            # For IKEv2 tunnels, if we are behind symmetric NAT, and if we are IKE responder,
            # we have to send VxLAN packet to the remote end of the tunnel in order to pinhole the NAT.
            # Otherwise the remote end, which is IKE initiator, will be not able to intiate the IKE negotiation.
            encryption_mode = tunnel.get("encryption-mode", "psk")
            role = tunnel["ikev2"]["role"]
            if encryption_mode == "ikev2" and role == "responder":
                fwglobals.log.debug("ikev2 tunnel %d responder side is down on dev %s"%(tunnel_id, dev_id))
                self.sym_nat_tunnels_cache[tunnel_id] = {
                            'src'       : tunnel['src'],
                            'dst'       : tunnel['dst'],
                            'dstPort'   : tunnel['dstPort'],
                            'vni'       : self._get_vni(tunnel_id, encryption_mode)
                        }


    def _is_useStun(self, dev_id):
        """ check router DB for 'useStun' flag for an interface bus address
        : param dev_id : Bus address to check the flag for
        : return : 'useStun' value in DB, or False if not found -> Bool
        """
        interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
        if interfaces and interfaces[0].get('useStun','') != '':
            return interfaces[0].get('useStun')

        if interfaces and interfaces[0].get('type','WAN') == 'LAN':
            return False

        # The dev_id was not found in the DB, so it is an unassigned interface. Let's check
        # if it has a GW configured. It so, it is a WAN interface, and we will return 'True'
        name = fwutils.dev_id_to_linux_if(dev_id)
        if not name:
            name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True)
        if not name:
            return False
        gw, _ = fwutils.get_interface_gateway(name)
        if not gw:
            return False
        return True

    def _get_tunnel_source_dev_id(self, tunnel_id):
        """ get the interface bus address of the tunnel's source IP address
        : param tunnel_id : the ID of the tunnel for which we need the dev id for
        : return : Bus address, or None -> str
        """
        tunnel = fwglobals.g.router_cfg.get_tunnel(tunnel_id)
        if tunnel:
            return tunnel.get('dev_id')
        return None

    def _map_ip_addr_to_dev_id(self, ip_no_mask):
        """ Utility function to try and map existing IP address to bus address.
        : param ip_no_mask : ip address without mask
        : return : Bus address or None -> str
        """
        dev_id_ip_dict = fwutils.get_all_interfaces()
        for dev_id in dev_id_ip_dict:
            if dev_id_ip_dict[dev_id].get('addr') == ip_no_mask:
                return dev_id
        return None

    def _get_vni(self, tunnel_id, encryption_mode):
        if encryption_mode == "none":
            return tunnel_id*2
        else:
            return tunnel_id*2+1

    def _probe_symmetric_nat(self):
        """ Assume that tunnel in down state has remote edge behind symmetric NAT.
            Try to discover the remote edge address/port from incoming packets.
        """
        if not self.sym_nat_cache:
            return

        probe_tunnels = {}

        for dev_id in list(self.sym_nat_cache):
            cached_addr = self.sym_nat_cache.get(dev_id)
            if not cached_addr or cached_addr.get('probe_time', 0) == 0:
                continue

            if time.time() >= cached_addr['probe_time']:
                src_ip = cached_addr['local_ip']
                src_port = 4789
                dev_name = fwutils.get_interface_name(src_ip)

                fwglobals.log.debug("Tunnel: discovering remote ip for tunnels with src %s:%s on device %s" \
                    %(src_ip, src_port, dev_name))
                probe_tunnels_dev = fwstun.get_remote_ip_info(src_ip, src_port, dev_name)
                fwglobals.log.debug("Tunnel: discovered tunnels %s on dev %s" %(probe_tunnels_dev, dev_name))
                probe_tunnels.update(probe_tunnels_dev)
                cached_addr['probe_time'] = 0

        self._handle_symmetric_nat_response(probe_tunnels)

    def _handle_symmetric_nat_response(self, probe_tunnels):
        """ Handle response for symmetric NAT probe. Reset all the counters,
        update the results, and set the 'success' flag to True.
        : param probe_tunnels  : List of discovered tunnels
        """
        tunnels       = fwglobals.g.router_cfg.get_tunnels()
        tunnel_stats  = fwtunnel_stats.tunnel_stats_get()
        if not tunnels or not probe_tunnels or not tunnel_stats:
            return

        for tunnel in tunnels:
            tunnel_id = tunnel['tunnel-id']
            encryption_mode = tunnel.get("encryption-mode", "psk")
            stats = tunnel_stats.get(tunnel_id)
            if stats and stats.get('status') == 'down':
                vni = self._get_vni(tunnel_id, encryption_mode)
                if vni in probe_tunnels:
                    if tunnel['dst'] != probe_tunnels[vni]["dst"] or tunnel['dstPort'] != probe_tunnels[vni]["dstPort"]:
                        fwglobals.log.debug("Remove tunnel: %s" %(tunnel))
                        fwglobals.g.handle_request({'message':'remove-tunnel', "params": tunnel})

                        tunnel['dst'] = probe_tunnels[vni]["dst"]
                        tunnel['dstPort'] = probe_tunnels[vni]["dstPort"]
                        fwglobals.log.debug("Add tunnel: %s" %(tunnel))
                        fwglobals.g.handle_request({'message':'add-tunnel', "params": tunnel})

    def _send_symmetric_nat(self):
        """ For IKEv2 tunnels, if we are behind symmetric NAT, and if we are IKE responder,
            we have to send VxLAN packet to the remote end of the tunnel in order to pinhole the NAT.
            Otherwise the remote end, which is IKE initiator, will be not able to intiate the IKE negotiation.
        """
        if not self.sym_nat_tunnels_cache:
            return

        for tunnel_id, tunnel in self.sym_nat_tunnels_cache.items():
            src_ip = tunnel['src']
            src_port = 4789
            dst_ip = tunnel['dst']
            dst_port = int(tunnel['dstPort'])
            dev_name = fwutils.get_interface_name(src_ip)
            vni = int(tunnel['vni'])
            vxLanMsgType = '08000000'
            vxLanReserved = '00'
            msg = vxLanMsgType + str(vni).zfill(6) + vxLanReserved
            fwutils.send_udp_packet(src_ip, src_port, dst_ip, dst_port, dev_name, msg)
