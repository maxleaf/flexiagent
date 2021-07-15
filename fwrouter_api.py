#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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

import copy
import enum
import os
import re
import time
import threading
import traceback
import json
import subprocess
import fwglobals
import fwutils
import fwnetplan

from fwapplications import FwApps
from fwmultilink import FwMultilink
from fwpolicies import FwPolicies
from vpp_api import VPP_API
from fwcfg_request_handler import FwCfgRequestHandler
from fwikev2 import FwIKEv2

import fwtunnel_stats
import fw_vpp_coredump_utils

fwrouter_translators = {
    'start-router':             {'module': __import__('fwtranslate_start_router'),    'api':'start_router'},
    'stop-router':              {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-interface':            {'module': __import__('fwtranslate_add_interface'),   'api':'add_interface'},
    'remove-interface':         {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-interface':         {'module': __import__('fwtranslate_add_interface'),   'api':'modify_interface'},
    'add-route':                {'module': __import__('fwtranslate_add_route'),       'api':'add_route'},
    'remove-route':             {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-tunnel':               {'module': __import__('fwtranslate_add_tunnel'),      'api':'add_tunnel'},
    'remove-tunnel':            {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'modify-tunnel':            {'module': __import__('fwtranslate_add_tunnel'),      'api':'modify_tunnel'},
    'add-dhcp-config':          {'module': __import__('fwtranslate_add_dhcp_config'), 'api':'add_dhcp_config'},
    'remove-dhcp-config':       {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-application':          {'module': __import__('fwtranslate_add_app'),         'api':'add_app'},
    'remove-application':       {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-multilink-policy':     {'module': __import__('fwtranslate_add_policy'),      'api':'add_policy'},
    'remove-multilink-policy':  {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-switch':               {'module': __import__('fwtranslate_add_switch'),      'api':'add_switch'},
    'remove-switch':            {'module': __import__('fwtranslate_revert') ,         'api':'revert'},
    'add-firewall-policy':      {'module': __import__('fwtranslate_firewall_policy'), 'api':'add_firewall_policy'},
    'remove-firewall-policy':   {'module': __import__('fwtranslate_revert'),          'api':'revert'},
    'add-ospf':                 {'module': __import__('fwtranslate_add_ospf'),        'api':'add_ospf'},
    'remove-ospf':              {'module': __import__('fwtranslate_revert'),          'api':'revert'},
}

class FwRouterState(enum.Enum):
    STARTING  = 1
    STARTED   = 2
    STOPPING  = 3
    STOPPED   = 4
    FAILED    = 666

class FWROUTER_API(FwCfgRequestHandler):
    """This is Router API class representation.
    The Router API class provides control over vpp.
    That includes:
    - start and stop vpp functionality
    - wrappers for vpp configuration APIs
    - collecting statistics about vpp activity
    - monitoring vpp and restart it on exceptions
    - restoring vpp configuration on vpp restart or on device reboot

    :param multilink_db_file: name of file that stores persistent multilink data
    """
    def __init__(self, cfg, multilink_db_file):
        """Constructor method
        """
        self.vpp_api         = VPP_API()
        self.multilink       = FwMultilink(multilink_db_file)
        self.router_state    = FwRouterState.STOPPED
        self.thread_watchdog     = None
        self.thread_tunnel_stats = None
        self.thread_dhcpc        = None
        self.thread_static_route = None

        FwCfgRequestHandler.__init__(self, fwrouter_translators, cfg, self._on_revert_failed)

        fwutils.reset_router_api_db() # Initialize cache that persists device reboot / daemon restart

    def finalize(self):
        """Destructor method
        """
        self._stop_threads()  # IMPORTANT! Do that before rest of finalizations!
        self.vpp_api.finalize()

    def watchdog(self):
        """Watchdog thread.
        Its function is to monitor if VPP process is alive.
        Otherwise it will start VPP and restore configuration from DB.
        """
        pending_coredump_processing = True
        while self.state_is_started() and not fwglobals.g.teardown:
            time.sleep(1)  # 1 sec
            try:           # Ensure thread doesn't exit on exception
                if not fwutils.vpp_does_run():      # This 'if' prevents debug print by restore_vpp_if_needed() every second
                    fwglobals.log.debug("watchdog: initiate restore")

                    self.vpp_api.disconnect_from_vpp()          # Reset connection to vpp to force connection renewal
                    fwutils.stop_vpp()                          # Release interfaces to Linux

                    fwutils.reset_traffic_control()             # Release LTE operations.
                    fwutils.remove_linux_bridges()              # Release bridges for wifi.
                    fwutils.stop_hostapd()                      # Stop access point service

                    self.state_change(FwRouterState.STOPPED)    # Reset state so configuration will applied correctly
                    self._restore_vpp()                         # Rerun VPP and apply configuration

                    # Process if any VPP coredump
                    pending_coredump_processing = fw_vpp_coredump_utils.vpp_coredump_process()
                elif pending_coredump_processing:
                    pending_coredump_processing = fw_vpp_coredump_utils.vpp_coredump_process()

                    fwglobals.log.debug("watchdog: restore finished")
            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

    def tunnel_stats_thread(self):
        """Tunnel statistics thread.
        Its function is to monitor tunnel state and RTT.
        It is implemented by pinging the other end of the tunnel.
        """
        self._fill_tunnel_stats_dict()
        while self.state_is_started() and not fwglobals.g.teardown:
            time.sleep(1)  # 1 sec
            try:           # Ensure thread doesn't exit on exception
                fwtunnel_stats.tunnel_stats_test()
            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

    def dhcpc_thread(self):
        """DHCP client thread.
        Its function is to monitor state of WAN interfaces with DHCP.
        """
        while self.state_is_started() and not fwglobals.g.teardown:
            time.sleep(1)  # 1 sec

            try:  # Ensure thread doesn't exit on exception
                apply_netplan = False
                wan_list = self.cfg_db.get_interfaces(type='wan')

                for wan in wan_list:
                    dhcp = wan.get('dhcp', 'no')
                    device_type = wan.get('deviceType')
                    if dhcp == 'no' or device_type == 'lte':
                        continue

                    name = fwutils.dev_id_to_tap(wan['dev_id'])
                    addr = fwutils.get_interface_address(name, log=False)
                    if not addr:
                        fwglobals.log.debug("dhcpc_thread: %s has no ip address" % name)
                        apply_netplan = True

                if apply_netplan:
                    fwutils.netplan_apply('dhcpc_thread')
                    time.sleep(10)

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

    def static_route_thread(self):
        """Static route thread.
        Its function is to monitor static routes.
        """
        while self.state_is_started() and not fwglobals.g.teardown:
            time.sleep(1)

            if int(time.time()) % 5 != 0:
                continue  # Check routes every 5 seconds, while checking teardown every second

            try:  # Ensure thread doesn't exit on exception
                fwutils.check_reinstall_static_routes()

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

    def restore_vpp_if_needed(self):
        """Restore VPP.
        If vpp doesn't run because of crash or device reboot,
        and it was started by management, start vpp and restore it's configuration.
        We do that by simulating 'start-router' request.
        Restore router state always to support multiple instances of Fwagent.

        :returns: `False` if no restore was performed, `True` otherwise.
        """

        # Restore failure state if recorded on disk:
        if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
            self.state_change(FwRouterState.FAILED, 'recorded failure was restored')
            fwglobals.log.excep("router is in failed state, try to start it from flexiManage \
                or use 'fwagent reset [--soft]' to recover")

        # If vpp runs already, or if management didn't request to start it, return.
        vpp_runs = fwutils.vpp_does_run()
        vpp_should_be_started = self.cfg_db.exists({'message': 'start-router'})
        if vpp_runs or not vpp_should_be_started:
            fwglobals.log.debug("restore_vpp_if_needed: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            if vpp_runs:
                self.state_change(FwRouterState.STARTED)
            if self.state_is_started():
                fwglobals.log.debug("restore_vpp_if_needed: vpp_pid=%s" % str(fwutils.vpp_pid()))
                self._start_threads()
                # We use here read_from_disk because we can't fill the netplan cache from scratch when vpp is running.
                # We use the original interface names in this cache,
                # but they don't exist when they are under dpdk control and replaced by vppsb interfaces.
                # Hence, we fill the cache with the backup in the disk
                fwnetplan.load_netplan_filenames(read_from_disk=vpp_runs)
            else:
                fwnetplan.restore_linux_netplan_files()
            return False

        self._restore_vpp()
        return True

    def _restore_vpp(self):
        fwglobals.log.info("===restore vpp: started===")
        try:
            with FwApps(fwglobals.g.APP_REC_DB_FILE) as db_app_rec:
                db_app_rec.clean()
            with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
                db_multilink.clean()
            with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
                db_policies.clean()
            fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()

            # Reboot might cause change of lte modem wan address,
            # so it will not match the netplan file that was before reboot.
            # That might cause contamination of vpp fib with wrong routes
            # during start-router execution. To avoid that we restore original
            # Linux netplan files to remove any lte related information.
            #
            fwnetplan.restore_linux_netplan_files()

            fwglobals.g.handle_request({'message': 'start-router'})
        except Exception as e:
            fwglobals.log.excep("restore_vpp_if_needed: %s" % str(e))
            self.state_change(FwRouterState.FAILED, "failed to restore vpp configuration")
        fwglobals.log.info("====restore vpp: finished===")

    def start_router(self):
        """Execute start router command.
        """
        fwglobals.log.info("start_router")
        if self.router_state == FwRouterState.STOPPED or self.router_state == FwRouterState.STOPPING:
            fwglobals.g.handle_request({'message': 'start-router'})
        fwglobals.log.info("start_router: started")

    def stop_router(self):
        """Execute stop router command.
        """
        fwglobals.log.info("stop_router")
        if self.router_state == FwRouterState.STARTED or self.router_state == FwRouterState.STARTING:
            fwglobals.g.handle_request({'message':'stop-router'})
        fwglobals.log.info("stop_router: stopped")

    def state_change(self, new_state, reason=''):
        log_reason = '' if not reason else ' (%s)' % reason
        fwglobals.log.debug("%s -> %s%s" % (str(self.router_state), str(new_state), log_reason))
        if self.router_state == new_state:
            return
        old_state = self.router_state
        self.router_state = new_state

        # On failure record the failure reason into file and kill vpp.
        # The file is used to persist reboot and to update flexiManage of
        # the router state.
        # On un-failure delete the file.
        #
        if new_state == FwRouterState.FAILED:
            if not os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                with open(fwglobals.g.ROUTER_STATE_FILE, 'w') as f:
                    if fwutils.valid_message_string(reason):
                        fwutils.file_write_and_flush(f, reason + '\n')
                    else:
                        fwglobals.log.excep("Not valid router failure reason string: '%s'" % reason)
            fwutils.stop_vpp()
        elif old_state == FwRouterState.FAILED:
            if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                os.remove(fwglobals.g.ROUTER_STATE_FILE)

    def state_is_started(self):
        return (self.router_state == FwRouterState.STARTED)

    def state_is_stopped(self):
        return (self.router_state == FwRouterState.STOPPED)

    def state_is_starting_stopping(self):
        return (self.router_state == FwRouterState.STARTING or \
                self.router_state == FwRouterState.STOPPING)

    def call(self, request, dont_revert_on_failure=False):
        """Executes router configuration request: 'add-X','remove-X' or 'modify-X'.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        prev_logger = self.set_request_logger(request)   # Use request specific logger (this is to offload heavy 'add-application' logging)
        try:

            # First of all strip out requests that have no impact on configuration,
            # like 'remove-X' for not existing configuration items and 'add-X' for
            # existing configuration items.
            #
            new_request = self._strip_noop_request(request)
            if not new_request:
                self.log.debug("call: ignore no-op request: %s" % json.dumps(request))
                self.set_logger(prev_logger)  # Restore logger if was changed
                return { 'ok': 1, 'message':'request has no impact' }
            request = new_request

            # Now find out if:
            # 1. VPP should be restarted as a result of request execution.
            #    It should be restarted on addition/removal interfaces in order
            #    to capture new interface /release old interface back to Linux.
            # 2. Agent should reconnect proactively to flexiManage.
            #    It should reconnect on add-/remove-/modify-interface, as they might
            #    impact on connection under the connection legs. So it might take
            #    a time for connection to detect the change, to report error and to
            #    reconnect again by the agent infinite connection loop with random
            #    sleep between retrials.
            # 3. Gateway of WAN interfaces are going to be modified.
            #    In this case we have to ping the GW-s after modification.
            #    See explanations on that workaround later in this function.
            #
            (restart_router, reconnect_agent, gateways) = self._analyze_request(request)

            # Some requests require preprocessing.
            # For example before handling 'add-application' the currently configured
            # applications should be removed. The simplest way to do that is just
            # to simulate 'remove-application' receiving. Hence need in preprocessing.
            # The preprocessing adds the simulated 'remove-application' request to the
            # the real received 'add-application' forming thus new aggregation request.
            #
            request = self._preprocess_request(request)

            # Stop vpp if it should be restarted.
            #
            if restart_router:
                fwglobals.g.router_api._call_simple({'message':'stop-router'})

            # Finally handle the request
            #

            reply = FwCfgRequestHandler.call(self, request, dont_revert_on_failure)

            # Start vpp if it should be restarted
            #
            if restart_router:
                fwglobals.g.router_api._call_simple({'message':'start-router'})

            # Reconnect agent if needed
            #
            if reconnect_agent:
                fwglobals.g.fwagent.reconnect()


            ########################################################################
            # Workaround for following problem:
            # Today 'modify-interface' request is replaced by pair of correspondent
            # 'remove-interface' and 'add-interface' requests. if 'modify-interface'
            # request changes IP or GW of WAN interface, the correspondent
            # 'remove-interface' removes GW from the Linux neighbor table, but the
            # consequent 'add-interface' does not add it back.
            # As a result the VPP FIB is stuck with DROP rule for that interface,
            # and traffic on that interface is dropped.
            # The workaround below enforces Linux to update the neighbor table with
            # the latest GW-s. That causes VPPSB to propagate the ARP information
            # into VPP FIB.
            # Note we do this even if 'modify-interface' failed, as before failure
            # it might succeed to remove few interfaces from Linux.
            ########################################################################
            if gateways:
                # Delay 5 seconds to make sure Linux interfaces were initialized
                time.sleep(5)
                for gw in gateways:
                    try:
                        cmd = 'ping -c 3 %s' % gw
                        output = subprocess.check_output(cmd, shell=True).decode()
                        self.log.debug("call: %s: %s" % (cmd, output))
                    except Exception as e:
                        self.log.debug("call: %s: %s" % (cmd, str(e)))

        except Exception as e:
            self.set_logger(prev_logger)  # Restore logger if was changed
            raise e

        self.set_logger(prev_logger)  # Restore logger if was changed
        return reply


    def _fill_tunnel_stats_dict(self):
        """Get tunnels their corresponding loopbacks ip addresses
        to be used by tunnel statistics thread.
        """
        fwtunnel_stats.tunnel_stats_clear()
        tunnels = self.cfg_db.get_tunnels()
        for params in tunnels:
            id   = params['tunnel-id']
            addr = params['loopback-iface']['addr']
            fwtunnel_stats.tunnel_stats_add(id, addr)

    def _call_simple(self, request):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        try:
            whitelist = None
            req = request['message']

            router_was_started = fwutils.vpp_does_run()

            # The 'add-application' and 'add-multilink-policy' requests should
            # be translated and executed only if VPP runs, as the translations
            # depends on VPP API-s output. Therefore if VPP does not run,
            # just save the requests in database and return.
            #
            if router_was_started == False and \
                (req == 'add-application' or
                req == 'add-multilink-policy' or
                req == 'add-firewall-policy'):
                self.cfg_db.update(request)
                return {'ok':1}

            execute = False
            filter = None
            if router_was_started or req == 'start-router':
                execute = True
            elif re.match('remove-',  req):
                filter = 'must'
                execute = True

            FwCfgRequestHandler._call_simple(self, request, execute, filter)

        except Exception as e:
            err_str = "FWROUTER_API::_call_simple: %s" % str(traceback.format_exc())
            self.log.error(err_str)
            if req == 'start-router':
                self.state_change(FwRouterState.FAILED, 'failed to start router')
            raise e

        return {'ok':1}

    def _on_revert_failed(self, reason):
        self.state_change(FwRouterState.FAILED, "revert failed: %s" % reason)

    def _analyze_request(self, request):
        """Analyzes received request either simple or aggregated in order to
        deduce if some special actions, like router restart, are needed as a
        result or request handling. The collected information is returned back
        to caller in form of booleans. See more details in description of return
        value.

        :param request: The request received from flexiManage.

        :returns: tuple of flags as follows:
            restart_router - VPP should be restarted as 'add-interface' or
                        'remove-interface' was detected in request.
                        These operations require vpp restart as vpp should
                        capture or should release interfaces back to Linux.
            reconnect_agent - Agent should reconnect proactively to flexiManage
                        as add-/remove-/modify-interface was detected in request.
                        These operations might cause connection failure on TCP
                        timeout, which might take up to few minutes to detect!
                        As well the connection retrials are performed with some
                        interval. To short no connectivity periods we close and
                        retries the connection proactively.
            gateways - List of gateways to be pinged after request handling
                        in order to solve following problem:
                        today 'modify-interface' request is replaced by pair of
                        correspondent 'remove-interface' and 'add-interface'
                        requests. The 'remove-interface' removes GW from the
                        Linux neighbor table, but the consequent 'add-interface'
                        request does not add it back. As a result the VPP FIB is
                        stuck with DROP rule for that interface, and traffic
                        which is outgoing on that interface is dropped.
                        So we ping the gateways to enforces Linux to update the
                        neighbor table. That causes VPPSB to propagate the ARP
                        information into VPP FIB.
        """

        def _should_reconnect_agent_on_modify_interface(new_params):
            old_params = self.cfg_db.get_interfaces(dev_id=new_params['dev_id'])[0]
            if new_params.get('addr') and new_params.get('addr') != old_params.get('addr'):
                return True
            if new_params.get('gateway') != old_params.get('gateway'):
                return True
            if new_params.get('metric') != old_params.get('metric'):
                return True
            return False


        (restart_router, reconnect_agent, gateways) = \
        (False,          False,           [])

        if self.state_is_started():
            if re.match('(add|remove)-interface', request['message']):
                restart_router  = True
                reconnect_agent = True
            elif request['message'] == 'modify-interface':
                reconnect_agent = _should_reconnect_agent_on_modify_interface(request['params'])
            elif request['message'] == 'aggregated':
                for _request in request['params']['requests']:
                    if re.match('(add|remove)-interface', _request['message']):
                        restart_router = True
                        reconnect_agent = True
                    elif _request['message'] == 'modify-interface':
                        if _should_reconnect_agent_on_modify_interface(_request['params']):
                            reconnect_agent = True

        if re.match('(start|stop)-router', request['message']):
            reconnect_agent = True
        elif re.match('modify-interface', request['message']):
            gw = request['params'].get('gateway')
            if gw:
                gateways.append(gw)
        elif request['message'] == 'aggregated':
            for _request in request['params']['requests']:
                if re.match('(start|stop)-router', _request['message']):
                    reconnect_agent = True
                elif re.match('modify-interface', _request['message']):
                    gw = _request['params'].get('gateway')
                    if gw:
                        gateways.append(gw)

        return (restart_router, reconnect_agent, gateways)

    def _preprocess_request(self, request):
        """Some requests require preprocessing. For example before handling
        'add-application' the currently configured applications should be removed.
        The simplest way to do that is just to simulate 'remove-application'
        receiving: before the 'add-application' is processed we have
        to process the simulated 'remove-application' request.
        To do that we just create the new aggregated request and put the simulated
        'remove-application' request and the original 'add-application' request
        into it.
            Note the main benefit of this approach is automatic revert of
        the simulated requests if the original request fails.

        :param request: The original request received from flexiManage

        :returns: request - The new aggregated request and it's parameters.
                        Note the parameters are list of requests that might be
                        a mix of simulated requests and original requests.
                        This mix should include one original request and one or
                        more simulated requests.
        """

        def _preprocess_modify_X(request):
            _req    = request['message']
            _params = request['params']
            remove_req = _req.replace("modify-", "remove-")
            old_params = self.cfg_db.get_request_params(request)
            add_req    = _req.replace("modify-", "add-")
            new_params = copy.deepcopy(old_params)
            new_params.update(_params)

            return [
                { 'message': remove_req, 'params' : old_params },
                { 'message': add_req,    'params' : new_params }
            ]


        req     = request['message']
        params  = request.get('params')
        changes = {}

        # 'modify-X' preprocessing:
        #  1. Replace 'modify-X' with 'remove-X' and 'add-X' pair.
        #     Implement real modification on demand :)
        #
        if re.match('modify-interface', req):
            req     = 'aggregated'
            params  = { 'requests' : _preprocess_modify_X(request) }
            request = {'message': req, 'params': params}
            changes['insert'] = True
            # DON'T RETURN HERE !!! FURTHER PREPROCESSING IS NEEDED !!!
        elif req == 'aggregated':
            new_requests = []
            for _request in params['requests']:
                if re.match('modify-interface', _request['message']):
                    new_requests += _preprocess_modify_X(_request)
                    changes['insert'] = True
                else:
                    new_requests.append(_request)
            params['requests'] = new_requests

        # For aggregated request go over all remove-X requests and replace their
        # parameters with current configuration for X stored in database.
        # The remove-* request might have partial set of parameters only.
        # For example, 'remove-interface' has 'dev_id' parameter only and
        # has no IP, LAN/WAN type, etc.
        # That makes it impossible to revert these partial remove-X requests
        # on aggregated message rollback that might happen due to failure in
        # in one of the subsequent  requests in the aggregation list.
        #
        if req == 'aggregated':
            for _request in params['requests']:
                if re.match('remove-', _request['message']):
                    _request['params'] = self.cfg_db.get_request_params(_request)

        ########################################################################
        # The code below preprocesses 'add-application' and 'add-multilink-policy'
        # requests. This preprocessing just adds 'remove-application' and
        # 'remove-multilink-policy' requests to clean vpp before original
        # request. This should happen only if vpp was started and
        # initial configuration was applied to it during start. If that is not
        # the case, there is nothing to remove yet, so removal will fail.
        ########################################################################
        if self.state_is_stopped():
            if changes.get('insert'):
                self.log.debug("_preprocess_request: Simple request was \
                        replaced with %s" % json.dumps(request))
            return request

        multilink_policy_params = self.cfg_db.get_multilink_policy()
        firewall_policy_params = self.cfg_db.get_firewall_policy()

        # 'add-application' preprocessing:
        # 1. The currently configured applications should be removed firstly.
        #    We do that by adding simulated 'remove-application' request in
        #    front of the original 'add-application' request.
        # 2. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        application_params = self.cfg_db.get_applications()
        if application_params:
            if req == 'add-application':
                pre_requests = [ { 'message': 'remove-application', 'params' : application_params } ]
                process_requests = [ { 'message': 'add-application', 'params' : params } ]
                if multilink_policy_params:
                    pre_requests.insert(0, { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params })
                    process_requests.append({ 'message': 'add-multilink-policy', 'params' : multilink_policy_params })
                if firewall_policy_params:
                    pre_requests.insert(0, { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params })
                    process_requests.append({ 'message': 'add-firewall-policy', 'params' : firewall_policy_params })

                updated_requests = pre_requests + process_requests
                params = { 'requests' : updated_requests }
                request = {'message': 'aggregated', 'params': params}
                self.log.debug("_preprocess_request: Application request \
                        was replaced with %s" % json.dumps(request))
                return request

        # 'add-multilink-policy' preprocessing:
        # 1. The currently configured policy should be removed firstly.
        #    We do that by adding simulated 'remove-multilink-policy' request in
        #    front of the original 'add-multilink-policy' request.
        #
        if multilink_policy_params:
            if req == 'add-multilink-policy':
                updated_requests = [
                    { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                    { 'message': 'add-multilink-policy',    'params' : params }
                ]
                request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
                self.log.debug("_preprocess_request: Multilink \
                        request was replaced with %s" % json.dumps(request))
                return request

        # Setup remove-firewall-policy before executing add-firewall-policy
        if firewall_policy_params:
            if req == 'add-firewall-policy':
                updated_requests = [
                    { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params },
                    { 'message': 'add-firewall-policy',    'params' : params }
                ]
                request = {'message': 'aggregated', 'params': { 'requests' : updated_requests }}
                self.log.debug("_preprocess_request: Firewall request \
                        was replaced with %s" % json.dumps(request))
                return request

        # 'add/remove-application' preprocessing:
        # 1. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        if multilink_policy_params or firewall_policy_params:
            if re.match('(add|remove)-(application)', req):
                if multilink_policy_params and firewall_policy_params:
                    pre_add_requests = [
                        { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                        { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params },
                    ]
                    post_add_requests = [
                        { 'message': 'add-multilink-policy', 'params' : multilink_policy_params },
                        { 'message': 'add-firewall-policy', 'params' : firewall_policy_params },
                    ]
                elif multilink_policy_params:
                    pre_add_requests = [
                        { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params }
                    ]
                    post_add_requests = [
                        { 'message': 'add-multilink-policy', 'params' : multilink_policy_params }
                    ]
                else:
                    pre_add_requests = [
                        { 'message': 'remove-firewall-policy', 'params' : firewall_policy_params }
                    ]
                    post_add_requests = [
                        { 'message': 'add-firewall-policy', 'params' : firewall_policy_params },
                    ]
                params['requests'] = pre_add_requests
                params['requests'].append({ 'message': req, 'params' : params })
                params['requests'].extend(post_add_requests)
                request = {'message': 'aggregated', 'params': params}
                self.log.debug("_preprocess_request: Aggregated request \
                        with application config was replaced with %s" % json.dumps(request))
                return request

        # No preprocessing is needed for rest of simple requests, return.
        if req != 'aggregated':
            return request

        ########################################################################
        # Handle 'aggregated' request.
        # Perform same preprocessing for aggregated requests, either
        # original or created above.
        ########################################################################

        # Go over all requests and rearrange them, as order of requests is
        # important for proper configuration of VPP!
        # The list should start with the 'remove-X' requests in following order:
        #   [ 'add-firewall-policy', 'add-multilink-policy', 'add-application',
        #     'add-dhcp-config', 'add-route', 'add-tunnel', 'add-interface' ]
        # Than the 'add-X' requests should follow in opposite order:
        #   [ 'add-interface', 'add-tunnel', 'add-route', 'add-dhcp-config',
        #     'add-application', 'add-multilink-policy', 'add-firewall-policy' ]
        #
        add_order = [
            'add-ospf', 'add-switch', 'add-interface', 'add-tunnel', 'add-route',
            'add-dhcp-config', 'add-application', 'add-multilink-policy', 'add-firewall-policy', 'start-router'
        ]
        remove_order = [ re.sub('add-','remove-', name) for name in add_order if name != 'start-router' ]
        remove_order.append('stop-router')
        remove_order.reverse()
        requests     = []
        for req_name in remove_order:
            for _request in params['requests']:
                if re.match(req_name, _request['message']):
                    requests.append(_request)
        for req_name in add_order:
            for _request in params['requests']:
                if re.match(req_name, _request['message']):
                    requests.append(_request)
        if requests != params['requests']:
            params['requests'] = requests
        requests = params['requests']


        # We do few passes on requests to find insertion points if needed.
        # It is based on the first appearance of the preprocessor requests.
        #
        indexes = {
            'remove-switch'           : -1,
            'add-switch'              : -1,
            'remove-interface'        : -1,
            'add-interface'           : -1,
            'remove-application'      : -1,
            'add-application'         : -1,
            'remove-multilink-policy' : -1,
            'add-multilink-policy'    : -1,
            'remove-firewall-policy'  : -1,
            'add-firewall-policy'     : -1
        }

        reinstall_multilink_policy = True
        reinstall_firewall_policy = True

        for (idx , _request) in enumerate(requests):
            for req_name in indexes:
                if req_name == _request['message']:
                    if indexes[req_name] == -1:
                        indexes[req_name] = idx
                    if req_name == 'remove-multilink-policy':
                        reinstall_multilink_policy = False
                    if req_name == 'remove-firewall-policy':
                        reinstall_firewall_policy = False
                    break

        def _insert_request(requests, idx, req_name, params):
            requests.insert(idx, { 'message': req_name, 'params': params })
            # Update indexes
            indexes[req_name] = idx
            for name in indexes:
                if name != req_name and indexes[name] >= idx:
                    indexes[name] += 1
            changes['insert'] = True

        # Now preprocess 'add-application': insert 'remove-application' if:
        # - there are applications to be removed
        # - the 'add-application' was found in requests
        #
        if application_params and indexes['add-application'] > -1:
            if indexes['remove-application'] == -1:
                # If list has no 'remove-application' at all just add it before 'add-applications'.
                idx = indexes['add-application']
                _insert_request(requests, idx, 'remove-application', application_params)
            elif indexes['remove-application'] > indexes['add-application']:
                # If list has 'remove-application' after the 'add-applications',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-application' was found after 'add-application': NOT SUPPORTED")

        # Now preprocess 'add-multilink-policy': insert 'remove-multilink-policy' if:
        # - there are policies to be removed
        # - there are interfaces to be removed or to be added
        # - the 'add-multilink-policy' was found in requests
        #
        def add_corresponding_remove_policy_message(requests, indexes, request_name, params):
            if request_name == 'multilink':
                add_request_name = 'add-multilink-policy'
                remove_request_name = 'remove-multilink-policy'
            elif request_name == 'firewall':
                add_request_name = 'add-firewall-policy'
                remove_request_name = 'remove-firewall-policy'
            if params and indexes[add_request_name] > -1:
                if indexes[remove_request_name] == -1:
                    # If list has no 'remove-X-policy' at all just add it before 'add-X-policy'.
                    idx = indexes[add_request_name]
                    _insert_request(requests, idx, remove_request_name, params)
                    changes['insert'] = True
                elif indexes[remove_request_name] > indexes[add_request_name]:
                    # If list has 'remove-X-policy' after the 'add-X-policy',
                    # it is not supported yet ;) Implement on demand
                    raise Exception("_preprocess_request: 'remove-X-policy' was found after \
                            'add-X-policy': NOT SUPPORTED")
                self.log.debug("_add_corresponding_remove_policy_message: %s" % request_name)

        add_corresponding_remove_policy_message(requests, indexes, 'multilink',
                multilink_policy_params)

        add_corresponding_remove_policy_message(requests, indexes, 'firewall',
                firewall_policy_params)

        # Now preprocess 'add/remove-application' and 'add/remove-interface':
        # reinstall multilink policy if:
        # - any of 'add/remove-application', 'add/remove-interface' appears in request
        # - the original request does not have 'remove-multilink-policy'
        #
        if multilink_policy_params or firewall_policy_params:
            # Firstly find the right place to insert the 'remove-multilink-policy' - idx.
            # It should be the first appearance of one of the preprocessing requests.
            # As well find the right place to insert the 'add-multilink-policy' - idx_last.
            # It should be the last appearance of one of the preprocessing requests.
            #
            idx = 10000
            idx_last = -1
            for req_name in indexes:
                if indexes[req_name] > -1:
                    if indexes[req_name] < idx:
                        idx = indexes[req_name]
                    if indexes[req_name] > idx_last:
                        idx_last = indexes[req_name]
            if idx == 10000:
                # No requests to preprocess were found, return
                return request


            def update_policy_message_positions(requests, request_name, params,
                    indexes, max_idx, reinstall_needed):
                insert_count = 0
                if request_name == 'multilink':
                    add_request_name = 'add-multilink-policy'
                    remove_request_name = 'remove-multilink-policy'
                elif request_name == 'firewall':
                    add_request_name = 'add-firewall-policy'
                    remove_request_name = 'remove-firewall-policy'

                if indexes[remove_request_name] > idx:
                    # Move 'remove-X-policy' to the min position:
                    # insert it as the min position and delete the original 'remove-X-policy'.
                    idx_policy = indexes[remove_request_name]
                    _insert_request(requests, idx, remove_request_name, params)
                    del requests[idx_policy + 1]
                if indexes[add_request_name] > -1 and indexes[add_request_name] < max_idx:
                    # We exploit the fact that only one 'add-X-policy' is possible
                    # Move 'add-multilink-policy' to the idx_last+1 position to be after all other 'add-X':
                    # insert it at the idx_last position and delete the original 'add-multilink-policy'.
                    idx_policy = indexes[add_request_name]
                    _insert_request(requests, max_idx + 1, add_request_name, params)
                    del requests[idx_policy]
                if indexes[remove_request_name] == -1:
                    _insert_request(requests, idx, remove_request_name, params)
                    insert_count += 1
                    max_idx += 1
                if indexes[add_request_name] == -1 and reinstall_needed:
                    _insert_request(requests, max_idx + 1, add_request_name, params)
                    insert_count += 1
                return insert_count

            # Now add policy reinstallation if needed.
            if multilink_policy_params:
                idx_last +=update_policy_message_positions(requests, 'multilink',
                        multilink_policy_params, indexes, idx_last, reinstall_multilink_policy)

            if firewall_policy_params:
                update_policy_message_positions(requests, 'firewall', firewall_policy_params,
                        indexes, idx_last, reinstall_firewall_policy)

        if changes.get('insert'):
            self.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
        return request

    def _start_threads(self):
        """Start all threads.
        """
        if self.thread_watchdog is None or self.thread_watchdog.is_alive() == False:
            self.thread_watchdog = threading.Thread(target=self.watchdog, name='Watchdog Thread')
            self.thread_watchdog.start()
        if self.thread_tunnel_stats is None or self.thread_tunnel_stats.is_alive() == False:
            self.thread_tunnel_stats = threading.Thread(target=self.tunnel_stats_thread, name='Tunnel Stats Thread')
            self.thread_tunnel_stats.start()
        if self.thread_dhcpc is None or self.thread_dhcpc.is_alive() == False:
            self.thread_dhcpc = threading.Thread(target=self.dhcpc_thread, name='DHCP Client Thread')
            self.thread_dhcpc.start()
        if self.thread_static_route is None or self.thread_static_route.is_alive() == False:
            self.thread_static_route = threading.Thread(target=self.static_route_thread, name='Static route Thread')
            self.thread_static_route.start()

    def _stop_threads(self):
        """Stop all threads.
        """
        if self.state_is_started(): # Ensure thread loops will break
            self.state_change(FwRouterState.STOPPED)

        if self.thread_watchdog:
            self.thread_watchdog.join()
            self.thread_watchdog = None

        if self.thread_tunnel_stats:
            self.thread_tunnel_stats.join()
            self.thread_tunnel_stats = None

        if self.thread_dhcpc:
            self.thread_dhcpc.join()
            self.thread_dhcpc = None

        if self.thread_static_route:
            self.thread_static_route.join()
            self.thread_static_route = None

    def _on_start_router_before(self):
        """Handles pre start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTING)

        # Clean VPP API trace from previous invocation (if exists)
        #
        os.system('sudo rm -rf /tmp/*%s' % fwglobals.g.VPP_TRACE_FILE_EXT)

        # Clean FRR config files
        if os.path.exists(fwglobals.g.FRR_CONFIG_FILE):
            os.remove(fwglobals.g.FRR_CONFIG_FILE)
        if os.path.exists(fwglobals.g.FRR_OSPFD_FILE):
            os.remove(fwglobals.g.FRR_OSPFD_FILE)

        fwutils.reset_router_api_db(enforce=True)

        fwutils.vmxnet3_unassigned_interfaces_up()

        fwnetplan.load_netplan_filenames()

    def _on_start_router_after(self):
        """Handles post start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTED)
        self._start_threads()
        fwutils.clear_linux_interfaces_cache()
        self.log.info("router was started: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _on_stop_router_before(self):
        """Handles pre-VPP stop activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STOPPING)
        with FwIKEv2() as ike:
            ike.clean()
        self._stop_threads()
        fwutils.reset_dhcpd()
        fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()
        self.log.info("router is being stopped: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _on_stop_router_after(self):
        """Handles post-VPP stop activities.
        :returns: None.
        """
        self.router_stopping = False
        fwutils.reset_traffic_control()
        fwutils.remove_linux_bridges()
        fwutils.stop_hostapd()

        # keep LTE connectivity on linux interface
        fwglobals.g.system_api.restore_configuration(types=['add-lte'])

        self.state_change(FwRouterState.STOPPED)
        fwglobals.g.cache.dev_id_to_vpp_tap_name.clear()
        fwglobals.g.cache.dev_id_to_vpp_if_name.clear()
        fwutils.clear_linux_interfaces_cache()

    def _on_add_interface_after(self, type, sw_if_index):
        """add-interface postprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self._update_cache_sw_if_index(sw_if_index, type, True)

    def _on_remove_interface_before(self, type, sw_if_index):
        """remove-interface preprocessing

        :param type:        "wan"/"lan"
        :param sw_if_index: vpp sw_if_index of the interface
        """
        self._update_cache_sw_if_index(sw_if_index, type, False)

    def _on_add_tunnel_after(self, sw_if_index):
        """add-tunnel postprocessing

        :param tunnel_id:   tunnel ID received from flexiManage. Not in use for now.
        :param sw_if_index: vpp sw_if_index of the tunnel loopback interface
        """
        vpp_if_name = self._update_cache_sw_if_index(sw_if_index, 'tunnel', True)
        fwutils.tunnel_change_postprocess(False, vpp_if_name)

    def _on_remove_tunnel_before(self, sw_if_index):
        """remove-tunnel preprocessing

        :param tunnel_id:   tunnel ID received from flexiManage. Not in use for now.
        :param sw_if_index: vpp sw_if_index of the tunnel loopback interface
        """
        vpp_if_name = self._update_cache_sw_if_index(sw_if_index, 'tunnel', False)
        fwutils.tunnel_change_postprocess(True, vpp_if_name)

    def _update_cache_sw_if_index(self, sw_if_index, type, add):
        """Updates persistent caches that store mapping of sw_if_index into
        name of vpp interface and via versa.

        :param sw_if_index: vpp sw_if_index of the vpp software interface
        :param type:        "wan"/"lan"/"tunnel" - type of interface
        :param add:         True to add to cache, False to remove from cache
        """
        router_api_db  = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        cache_by_index = router_api_db['sw_if_index_to_vpp_if_name']
        cache_by_name  = router_api_db['vpp_if_name_to_sw_if_index'][type]
        if add:
            vpp_if_name = fwutils.vpp_sw_if_index_to_name(sw_if_index)
            cache_by_name[vpp_if_name]  = sw_if_index
            cache_by_index[sw_if_index] = vpp_if_name
        else:
            vpp_if_name = cache_by_index[sw_if_index]
            del cache_by_name[vpp_if_name]
            del cache_by_index[sw_if_index]
        fwglobals.g.db['router_api'] = router_api_db
        return vpp_if_name

    def _on_apply_router_config(self):
        """Apply router configuration on successful VPP start.
        """
        types = [
            'add-ospf',
            'add-switch',
            'add-interface',
            'add-tunnel',
            'add-application',
            'add-multilink-policy',
            'add-firewall-policy'
            'add-route',            # Routes should come after tunnels as they might use them!
            'add-dhcp-config'
        ]
        messages = self.cfg_db.dump(types=types)
        for msg in messages:
            reply = fwglobals.g.router_api._call_simple(msg)
            if reply.get('ok', 1) == 0:  # Break and return error on failure of any request
                return reply

    def sync_full(self, incoming_requests):
        self.log.debug("_sync_device: start router full sync")

        restart_router = False
        if self.state_is_started():
            self.log.debug("_sync_device: restart_router=True")
            restart_router = True
            self.g.handle_request({'message':'stop-router'})

        FwCfgRequestHandler.sync_full(self, incoming_requests)

        if restart_router:
            self.g.handle_request({'message': 'start-router'})

        self.log.debug("_sync_device: router full sync succeeded")
