#! /usr/bin/python

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
import yaml
import json
import subprocess

import fwagent
import fwglobals
import fwutils
import fwnetplan
import fwtranslate_add_tunnel

from fwapplications import FwApps
from fwikev2 import FwIKEv2Tunnels
from fwmultilink import FwMultilink
from fwpolicies import FwPolicies
from vpp_api import VPP_API

import fwtunnel_stats

fwrouter_modules = {
    'fwtranslate_revert':          __import__('fwtranslate_revert') ,
    'fwtranslate_start_router':    __import__('fwtranslate_start_router'),
    'fwtranslate_add_interface':   __import__('fwtranslate_add_interface'),
    'fwtranslate_add_route':       __import__('fwtranslate_add_route'),
    'fwtranslate_add_tunnel':      __import__('fwtranslate_add_tunnel'),
    'fwtranslate_add_dhcp_config': __import__('fwtranslate_add_dhcp_config'),
    'fwtranslate_add_app':         __import__('fwtranslate_add_app'),
    'fwtranslate_add_policy':      __import__('fwtranslate_add_policy')
}

fwrouter_translators = {
    'start-router':             {'module':'fwtranslate_start_router',    'api':'start_router'},
    'stop-router':              {'module':'fwtranslate_revert',          'api':'revert'},
    'add-interface':            {'module':'fwtranslate_add_interface',   'api':'add_interface'},
    'remove-interface':         {'module':'fwtranslate_revert',          'api':'revert'},
    'modify-interface':         {'module':'fwtranslate_add_interface',   'api':'modify_interface'},
    'add-route':                {'module':'fwtranslate_add_route',       'api':'add_route'},
    'remove-route':             {'module':'fwtranslate_revert',          'api':'revert'},
    'add-tunnel':               {'module':'fwtranslate_add_tunnel',      'api':'add_tunnel'},
    'remove-tunnel':            {'module':'fwtranslate_revert',          'api':'revert'},
    'add-dhcp-config':          {'module':'fwtranslate_add_dhcp_config', 'api':'add_dhcp_config'},
    'remove-dhcp-config':       {'module':'fwtranslate_revert',          'api':'revert'},
    'add-application':          {'module':'fwtranslate_add_app',         'api':'add_app'},
    'remove-application':       {'module':'fwtranslate_revert',          'api':'revert'},
    'add-multilink-policy':     {'module':'fwtranslate_add_policy',      'api':'add_policy'},
    'remove-multilink-policy':  {'module':'fwtranslate_revert',          'api':'revert'},
}

class FwRouterState(enum.Enum):
    STARTING  = 1
    STARTED   = 2
    STOPPING  = 3
    STOPPED   = 4
    FAILED    = 666

class FWROUTER_API:
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
    def __init__(self, multilink_db_file):
        """Constructor method
        """
        self.vpp_api         = VPP_API()
        self.multilink       = FwMultilink(multilink_db_file)
        self.router_state    = FwRouterState.STOPPED
        self.thread_watchdog = None
        self.thread_tunnel_stats = None
        self.thread_dhcpc    = None
        self.thread_ikev2    = None

        # Initialize global data that persists device reboot / daemon restart.
        #
        if not 'router_api' in fwglobals.g.db:
            fwglobals.g.db['router_api'] = { 'sa_id' : 0 }

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
        while self.state_is_started():
            time.sleep(1)  # 1 sec
            try:           # Ensure thread doesn't exit on exception
                if not fwutils.vpp_does_run():      # This 'if' prevents debug print by restore_vpp_if_needed() every second
                    fwglobals.log.debug("watchdog: initiate restore")

                    self.vpp_api.disconnect_from_vpp()        # Reset connection to vpp to force connection renewal
                    self.router_state = FwRouterState.STOPPED # Reset state so configuration will applied correctly
                    self._restore_vpp()                       # Rerun VPP and apply configuration

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
        while self.state_is_started():
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
        while self.state_is_started():
            time.sleep(1)  # 1 sec

            try:  # Ensure thread doesn't exit on exception
                apply_netplan = False
                wan_list = fwglobals.g.router_cfg.get_interfaces(type='wan')

                for wan in wan_list:
                    dhcp = wan.get('dhcp', 'no')
                    if dhcp == 'no':
                        continue

                    name = fwutils.pci_to_tap(wan['pci'])
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

    def ikev2_thread(self):
        """IKEv2 client thread.
        Its function is to monitor state of IKEv2 GRE tunnels.
        """
        while self.state_is_started():
            time.sleep(1)  # 1 sec

            tunnels = fwglobals.g.router_api.vpp_api.vpp.api.gre_tunnel_dump(sw_if_index=(0xffffffff))
            fwglobals.log.debug("Tunnels:")
            fwglobals.log.debug(str(tunnels))
            tunnels_db = fwglobals.g.ikev2tunnels.get_tunnels()

            # Iterate through GRE tunnel DB and add new tunnels into bridges
            for tunnel_src, values in tunnels_db.items():
                is_found = False
                bridge_id = values['bridge_id']
                state = values['state']
                sw_if_index=None
                fwglobals.log.debug("tunnel_src %s, bridge_id %s, state %s" % (tunnel_src, bridge_id, state))
                for gre in tunnels:
                    fwglobals.log.debug("gre.tunnel.src %s, tunnel_src %s" % (gre.tunnel.src, tunnel_src))
                    if str(gre.tunnel.src) == str(tunnel_src):
                        sw_if_index = gre.tunnel.sw_if_index
                        is_found = True
                        fwglobals.log.debug("Found!")
                        break
                if state == 'down' and is_found:
                    fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=sw_if_index,
                                                                                    bd_id=bridge_id, enable=1, shg=1)
                    fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
                    fwglobals.g.ikev2tunnels.set_state(tunnel_src, 'up')
                    fwglobals.log.debug("tunnel_src %s was down and found" % str(tunnel_src))
                if state == 'up' and not is_found:
                    fwglobals.g.ikev2tunnels.set_state(tunnel_src, 'down')
                    fwglobals.log.debug("tunnel_src %s was up and not found" % str(tunnel_src))

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
        vpp_should_be_started = fwglobals.g.router_cfg.exists({'message': 'start-router'})
        if vpp_runs or not vpp_should_be_started:
            fwglobals.log.debug("restore_vpp_if_needed: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            if vpp_runs:
                self.state_change(FwRouterState.STARTED)
            if self.state_is_started():
                fwglobals.log.debug("restore_vpp_if_needed: vpp_pid=%s" % str(fwutils.vpp_pid()))
                self._start_threads()
                fwnetplan.load_netplan_filenames()
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
            with FwIKEv2Tunnels(fwglobals.g.IKEV2_DB_FILE) as db_ikev2:
                db_ikev2.clean()
            with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
                db_multilink.clean()
            with FwPolicies(fwglobals.g.POLICY_REC_DB_FILE) as db_policies:
                db_policies.clean()
            fwglobals.g.cache.pci_to_vpp_tap_name = {}
            self.call({'message':'start-router'})
        except Exception as e:
            fwglobals.log.excep("restore_vpp_if_needed: %s" % str(e))
            self.state_change(FwRouterState.FAILED, "failed to restore vpp configuration")
        fwglobals.log.info("====restore vpp: finished===")

    def start_router(self):
        """Execute start router command.
        """
        fwglobals.log.info("FWROUTER_API: start_router")
        if self.router_state == FwRouterState.STOPPED or self.router_state == FwRouterState.STOPPING:
            self.call({'message':'start-router'})
        fwglobals.log.info("FWROUTER_API: start_router: started")

    def stop_router(self):
        """Execute stop router command.
        """
        fwglobals.log.info("FWROUTER_API: stop_router")
        if self.router_state == FwRouterState.STARTED or self.router_state == FwRouterState.STARTING:
            self.call({'message':'stop-router'})
        fwglobals.log.info("FWROUTER_API: stop_router: stopped")

    def state_change(self, new_state, reason=''):
        log_reason = '' if not reason else ' (%s)' % reason
        fwglobals.log.debug("FWROUTER_API: %s -> %s%s" % (str(self.router_state), str(new_state), log_reason))
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

    def call(self, request):
        """Executes router configuration request: 'add-X','remove-X' or 'modify-X'.

        :param request: The request received from flexiManage.

        :returns: Status codes dictionary.
        """
        dont_revert_on_failure = request.get('internals', {}).get('dont_revert_on_failure', False)

        # First of all strip out requests that have no impact on configuration,
        # like 'remove-X' for not existing configuration items and 'add-X' for
        # existing configuration items.
        #
        new_request = self._strip_noop_request(request)
        if not new_request:
            fwglobals.log.debug("FWROUTER_API::call: ignore no-op request: %s" % json.dumps(request))
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
        if request['message'] == 'aggregated':
            reply = self._call_aggregated(request['params']['requests'], dont_revert_on_failure)
        else:
            reply = self._call_simple(request)

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
                    output = subprocess.check_output(cmd, shell=True)
                    fwglobals.log.debug("FWROUTER_API: call: %s: %s" % (cmd, output))
                except Exception as e:
                    fwglobals.log.debug("FWROUTER_API: call: %s: %s" % (cmd, str(e)))

        return reply


    def _call_aggregated(self, requests, dont_revert_on_failure=False):
        """Execute multiple requests.
        It do that as an atomic operation,
        i.e. if one of requests fails, all the previous are reverted.

        :param requests:    Request list.
        :param dont_revert_on_failure:  If True the succeeded requests in list
                            will not be reverted on failure of any request.
                            This bizare logic is used for device sync feature,
                            where there is no need to restore configuration,
                            as it is out of sync with the flexiManage.

        :returns: Status codes dictionary.
        """
        fwglobals.log.debug("FWROUTER_API: === start handling aggregated request ===")

        for (idx, request) in enumerate(requests):

            # Don't print too large requests, if needed check print on request receiving
            #
            if request['message'] == 'add-application' or request['message'] == 'remove-application':
                str_request = request['message'] + '...'
            else:
                str_request = json.dumps(request)

            try:
                fwglobals.log.debug("_call_aggregated: handle request %s" % str_request)
                self._call_simple(request)
            except Exception as e:
                if dont_revert_on_failure:
                    raise e
                # Revert previously succeeded simple requests
                fwglobals.log.error("_call_aggregated: failed to handle %s. reverting previous requests..." % str_request)
                for request in reversed(requests[0:idx]):
                    try:
                        op = request['message']
                        request['message'] = op.replace('add-','remove-') if re.match('add-', op) else op.replace('remove-','add-')
                        self._call_simple(request)
                    except Exception as e:
                        # on failure to revert move router into failed state
                        err_str = "_call_aggregated: failed to revert request %s while running rollback on aggregated request" % op
                        fwglobals.log.excep("%s: %s" % (err_str, format(e)))
                        self.state_change(FwRouterState.FAILED, err_str)
                        pass
                raise e

        fwglobals.log.debug("FWROUTER_API: === end handling aggregated request ===")
        return {'ok':1}

    def _fill_tunnel_stats_dict(self):
        """Get tunnels their corresponding loopbacks ip addresses
        to be used by tunnel statistics thread.
        """
        fwtunnel_stats.tunnel_stats_clear()
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        for params in tunnels:
            id   = params['tunnel-id']
            addr = params['loopback-iface']['addr']
            fwtunnel_stats.tunnel_stats_add(id, addr)

    def _call_simple(self, request):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: Status codes dictionary.
        """
        try:
            req = request['message']

            router_was_started = fwutils.vpp_does_run()

            # The 'add-application' and 'add-multilink-policy' requests should
            # be translated and executed only if VPP runs, as the translations
            # depends on VPP API-s output. Therefore if VPP does not run,
            # just save the requests in database and return.
            #
            if router_was_started == False and \
               (req == 'add-application' or req == 'add-multilink-policy'):
               fwglobals.g.router_cfg.update(request)
               return {'ok':1}

            # Translate request to list of commands to be executed
            cmd_list = self._translate(request)

            # Execute list of commands. Do it only if vpp runs.
            # Some 'remove-XXX' requests must be executed
            # even if vpp doesn't run right now. This is to clean stuff in Linux
            # that was added by correspondent 'add-XXX' request if the last was
            # applied to running vpp.
            #
            if router_was_started or req == 'start-router':
                self._execute(request, cmd_list)
                executed = True
            elif re.match('remove-',  req):
                self._execute(request, cmd_list, filter='must')
                executed = True
            else:
                executed = False

            # Save successfully handled configuration request into database.
            # We need it and it's translation to execute future 'remove-X'
            # requests as they are generated by reverting of correspondent
            # 'add-X' translations from last to the first. As well they are
            # needed to restore VPP configuration on device reboot or start of
            # crashed VPP by watchdog.
            #
            try:
                fwglobals.g.router_cfg.update(request, cmd_list, executed)
            except Exception as e:
                self._revert(cmd_list)
                raise e

            if re.match('(add|remove)-tunnel',  req):
                self._fill_tunnel_stats_dict()

        except Exception as e:
            err_str = "FWROUTER_API::_call_simple: %s" % str(traceback.format_exc())
            fwglobals.log.error(err_str)
            if req == 'start-router':
                self.state_change(FwRouterState.FAILED, 'failed to start router')
            raise e

        return {'ok':1}


    def _translate(self, request):
        """Translate request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        req    = request['message']
        params = request.get('params')

        api_defs = fwrouter_translators.get(req)
        assert api_defs, 'FWROUTER_API: there is no api for request "%s"' % req

        module = fwrouter_modules.get(fwrouter_translators[req]['module'])
        assert module, 'FWROUTER_API: there is no module for request "%s"' % req

        func = getattr(module, fwrouter_translators[req]['api'])
        assert func, 'FWROUTER_API: there is no api function for request "%s"' % req

        if fwrouter_translators[req]['api'] == 'revert':
            cmd_list = func(request)
            return cmd_list

        cmd_list = func(params) if params else func()
        return cmd_list

    def _translate_modify(self, request):
        """Translate modify request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        req         = request['message']
        params      = request.get('params')
        old_params  = fwglobals.g.router_cfg.get_params(request)

        # First of all check if the received parameters differs from the existing ones
        same = fwutils.compare_request_params(params, old_params)
        if same:
            return []

        api_defs = fwrouter_translators.get(req)
        if not api_defs:
            # This 'modify-X' is not supported (yet?)
            return []

        module = fwrouter_modules.get(fwrouter_translators[req]['module'])
        assert module, 'FWROUTER_API: there is no module for request "%s"' % req

        func = getattr(module, fwrouter_translators[req]['api'])
        assert func, 'FWROUTER_API: there is no api function for request "%s"' % req

        cmd_list = func(params, old_params)
        return cmd_list

    def _execute(self, request, cmd_list, filter=None):
        """Execute request.

        :param request:     The request received from flexiManage.
        :param cmd_list:    Commands list.
        :param filter:      Filter for commands to be executed.
                            If provided and if command has 'filter' field and
                            their values are same, the command will be executed.
                            If None, the check for filter is not applied.
        :returns: None.
        """
        cmd_cache = {}

        req = request['message']

        fwglobals.log.debug("FWROUTER_API: === start execution of %s ===" % (req))

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    fwglobals.log.debug("FWROUTER_API:_execute: filter out command by filter=%s (req=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
                                        (filter, req, cmd['name'], str(cmd.get('filter')), str(cmd.get('params'))))
                    continue

            try:
                # Firstly perform substitutions if needed.
                # The params might include 'substs' key with list of substitutions.
                self._substitute(cmd_cache, cmd.get('params'))

                if 'params' in cmd and type(cmd['params'])==dict:
                    params = fwutils.yaml_dump(cmd['params'])
                elif 'params' in cmd:
                    params = format(cmd['params'])
                else:
                    params = ''
                fwglobals.log.debug("FWROUTER_API:_execute: %s(%s)" % (cmd['name'], params))

                # Now execute command
                result = None if not 'cache_ret_val' in cmd else \
                    { 'result_attr' : cmd['cache_ret_val'][0] , 'cache' : cmd_cache , 'key' :  cmd['cache_ret_val'][1] }
                reply = fwglobals.g.handle_request({ 'message': cmd['name'], 'params':  cmd.get('params')}, result)
                if reply['ok'] == 0:        # On failure go back revert already executed commands
                    fwglobals.log.debug("FWROUTER_API: %s failed ('ok' is 0)" % cmd['name'])
                    raise Exception("API failed: %s" % reply['message'])

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['name'], format(cmd.get('params')), str(e), str(traceback.format_exc()))
                fwglobals.log.error(err_str)
                fwglobals.log.debug("FWROUTER_API: === failed execution of %s ===" % (req))
                if self.state_is_starting_stopping:
                    fwutils.dump()
                # On failure go back to the begining of list and revert executed commands.
                self._revert(cmd_list, idx)
                fwglobals.log.debug("FWROUTER_API: === finished revert of %s ===" % (req))
                raise Exception('failed to ' + cmd['descr'])

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self._substitute(cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    fwglobals.log.excep("_execute: failed to substitute revert command: %s\n%s, %s" % \
                                (str(t), str(e), str(traceback.format_exc())))
                    fwglobals.log.debug("FWROUTER_API: === failed execution of %s ===" % (req))
                    self._revert(cmd_list, idx)
                    raise e

        fwglobals.log.debug("FWROUTER_API: === end execution of %s ===" % (req))

    def _revert(self, cmd_list, idx_failed_cmd=-1):
        """Revert list commands that are previous to the failed command with
        index 'idx_failed_cmd'.
        :param cmd_list:        Commands list.
        :param idx_failed_cmd:  The index of command, execution of which
                                failed, so all commands in list before it
                                should be reverted.
        :returns: None.
        """
        idx_failed_cmd = idx_failed_cmd if idx_failed_cmd >= 0 else len(cmd_list)

        for t in reversed(cmd_list[0:idx_failed_cmd]):
            if 'revert' in t:
                rev_cmd = t['revert']
                try:
                    reply = fwglobals.g.handle_request(
                        { 'message': rev_cmd['name'], 'params': rev_cmd.get('params')})
                    if reply['ok'] == 0:
                        err_str = "handle_request(%s) failed" % rev_cmd['name']
                        fwglobals.log.error(err_str)
                        raise Exception(err_str)
                except Exception as e:
                    err_str = "_revert: exception while '%s': %s(%s): %s" % \
                                (t['cmd']['descr'], rev_cmd['name'], format(rev_cmd['params']), str(e))
                    fwglobals.log.excep(err_str)
                    self.state_change(FwRouterState.FAILED, "revert failed: %s" % t['cmd']['name'])

    def _strip_noop_request(self, request):
        """Checks if the request has no impact on configuration.
        For example, the 'remove-X'/'modify-X' for not existing configuration
        item or 'add-X' request for existing configuration item.

        :param request: The request received from flexiManage.

        :returns: request after stripping out no impact requests.
        """
        def _should_be_stripped(__request, aggregated_requests=None):
            req    = __request['message']
            params = __request.get('params', {})
            if re.match('(modify-|remove-)', req) and not fwglobals.g.router_cfg.exists(__request):
                # Ensure that the aggregated request does not include correspondent 'add-X' before.
                noop = True
                if aggregated_requests:
                    complement_req     = re.sub('(modify-|remove-)','add-', req)
                    complement_request = { 'message': complement_req, 'params': params }
                    if _exist(complement_request, aggregated_requests):
                        noop = False
                if noop:
                    return True
            elif re.match('add-', req) and fwglobals.g.router_cfg.exists(__request):
                # Ensure this is actually not modification request :)
                existing_params = fwglobals.g.router_cfg.get_request_params(__request)
                if fwutils.compare_request_params(existing_params, __request.get('params')):
                    # Ensure that the aggregated request does not include correspondent 'remove-X' before.
                    noop = True
                    if aggregated_requests:
                        complement_req     = re.sub('add-','remove-', req)
                        complement_request = { 'message': complement_req, 'params': params }
                        if _exist(complement_request, aggregated_requests):
                            noop = False
                    if noop:
                        return True
            elif re.match('start-router', req) and fwutils.vpp_does_run():
                return True
            elif re.match('modify-', req):
                # For modification request ensure that it goes to modify indeed:
                # translate request into commands to execute in order to modify
                # configuration item in Linux/VPP. If this list is empty,
                # the request can be stripped out.
                #
                cmd_list = self._translate_modify(__request)
                if not cmd_list:
                    # Save modify request into database, as it might contain parameters
                    # that don't impact on interface configuration in Linux or in VPP,
                    # like PublicPort, PublicIP, useStun, etc.
                    #
                    # !!!!!!!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!!!!!!!!
                    # We assume the 'modify-X' request includes full set of
                    # parameters and not only modified ones!
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    #
                    fwglobals.g.router_cfg.update(__request)
                    return True
            return False

        def _exist(__request, requests):
            """Checks if the list of requests has request for the same
            configuration item as the one denoted by the provided __request.
            """
            for r in requests:
                if (__request['message'] == r['message'] and
                    fwglobals.g.router_cfg.is_same_cfg_item(__request, r)):
                    return True
            return False


        if request['message'] != 'aggregated':
            if _should_be_stripped(request):
                fwglobals.log.debug("_strip_noop_request: request has no impact: %s" % json.dumps(request))
                return None
        else:  # aggregated request
            out_requests = []
            inp_requests = request['params']['requests']
            for _request in inp_requests:
                if _should_be_stripped(_request, inp_requests):
                    fwglobals.log.debug("_strip_noop_request: embedded request has no impact: %s" % json.dumps(request))
                else:
                    out_requests.append(_request)
            if not out_requests:
                fwglobals.log.debug("_strip_noop_request: aggregated request has no impact")
                return None
            if len(out_requests) < len(inp_requests):
                fwglobals.log.debug("_strip_noop_request: aggregation after strip: %s" % json.dumps(out_requests))
            request['params']['requests'] = out_requests
        return request

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
            old_params = fwglobals.g.router_cfg.get_interfaces(pci=new_params['pci'])[0]
            if new_params.get('addr') != old_params.get('addr'):
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
            old_params = fwglobals.g.router_cfg.get_request_params(request)
            add_req    = _req.replace("modify-", "add-")
            new_params = copy.deepcopy(old_params)
            new_params.update(_params.items())

            # Don't store internal 'sender' to avoid unnecessary sync-s
            #
            if 'internals' in new_params:
                del new_params['internals']

            return [
                { 'message': remove_req, 'params' : old_params },
                { 'message': add_req,    'params' : new_params }
            ]


        req     = request['message']
        params  = request.get('params')
        updated = False

        # 'modify-X' preprocessing:
        #  1. Replace 'modify-X' with 'remove-X' and 'add-X' pair.
        #     Implement real modification on demand :)
        #
        if re.match('modify-', req):
            req     = 'aggregated'
            params  = { 'requests' : _preprocess_modify_X(request) }
            request = {'message': req, 'params': params}
            updated = True
            # DON'T RETURN HERE !!! FURTHER PREPROCESSING IS NEEDED !!!
        elif req == 'aggregated':
            new_requests = []
            for _request in params['requests']:
                if re.match('modify-', _request['message']):
                    new_requests += _preprocess_modify_X(_request)
                else:
                    new_requests.append(_request)
            params['requests'] = new_requests

        # For aggregated request go over all remove-X requests and replace their
        # parameters with current configuration for X stored in database.
        # The remove-* request might have partial set of parameters only.
        # For example, 'remove-interface' has 'pci' parameter only and
        # has no IP, LAN/WAN type, etc.
        # That makes it impossible to revert these partial remove-X requests
        # on aggregated message rollback that might happen due to failure in
        # in one of the subsequent  requests in the aggregation list.
        #
        if req == 'aggregated':
            for _request in params['requests']:
                if re.match('remove-', _request['message']):
                    _request['params'] = fwglobals.g.router_cfg.get_request_params(_request)

        ########################################################################
        # The code below preprocesses 'add-application' and 'add-multilink-policy'
        # requests. This preprocessing just adds 'remove-application' and
        # 'remove-multilink-policy' requests to clean vpp before original
        # request. This should happen only if vpp was started and
        # initial configuration was applied to it during start. If that is not
        # the case, there is nothing to remove yet, so removal will fail.
        ########################################################################
        if self.state_is_stopped():
            if updated:
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
            return request

        multilink_policy_params = fwglobals.g.router_cfg.get_multilink_policy()

        # 'add-application' preprocessing:
        # 1. The currently configured applications should be removed firstly.
        #    We do that by adding simulated 'remove-application' request in
        #    front of the original 'add-application' request.
        # 2. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        application_params = fwglobals.g.router_cfg.get_applications()
        if application_params:
            if req == 'add-application':
                updated_requests = [
                    { 'message': 'remove-application', 'params' : application_params },
                    { 'message': 'add-application',    'params' : params }
                ]
                params = { 'requests' : updated_requests }

                if multilink_policy_params:
                    params['requests'][0:0]   = [ { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params }]
                    params['requests'][-1:-1] = [ { 'message': 'add-multilink-policy',    'params' : multilink_policy_params }]

                request = {'message': 'aggregated', 'params': params}
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
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
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
                return request

        # 'add/remove-application' preprocessing:
        # 1. The multilink policy should be re-installed: if exists, the policy
        #    should be removed before application removal/adding and should be
        #    added again after it.
        #
        if multilink_policy_params:
            if re.match('(add|remove)-(application)', req):
                params  = { 'requests' : [
                    { 'message': 'remove-multilink-policy', 'params' : multilink_policy_params },
                    { 'message': req, 'params' : params },
                    { 'message': 'add-multilink-policy',    'params' : multilink_policy_params }
                ] }
                request = {'message': 'aggregated', 'params': params}
                fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
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
        #   [ 'add-multilink-policy', 'add-application', 'add-dhcp-config', 'add-route', 'add-tunnel', 'add-interface' ]
        # Than the 'add-X' requests should follow in opposite order:
        #   [ 'add-interface', 'add-tunnel', 'add-route', 'add-dhcp-config', 'add-application', 'add-multilink-policy' ]
        #
        add_order    = [ 'add-interface', 'add-tunnel', 'add-route', 'add-dhcp-config', 'add-application', 'add-multilink-policy', 'start-router' ]
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
            fwglobals.log.debug("_preprocess_request: rearranged aggregation: %s" % json.dumps(requests))
            params['requests'] = requests
        requests = params['requests']


        # We do few passes on requests to find insertion points if needed.
        # It is based on the first appearance of the preprocessor requests.
        #
        indexes = {
            'remove-interface'        : -1,
            'add-interface'           : -1,
            'remove-application'      : -1,
            'add-application'         : -1,
            'remove-multilink-policy' : -1,
            'add-multilink-policy'    : -1
        }

        reinstall_multilink_policy = True

        for (idx , _request) in enumerate(requests):
            for req_name in indexes:
                if req_name == _request['message']:
                    if indexes[req_name] == -1:
                        indexes[req_name] = idx
                    if req_name == 'remove-multilink-policy':
                        reinstall_multilink_policy = False
                    break

        def _insert_request(requests, idx, req_name, params, updated):
            requests.insert(idx, { 'message': req_name, 'params': params })
            # Update indexes
            indexes[req_name] = idx
            for name in indexes:
                if name != req_name and indexes[name] >= idx:
                    indexes[name] += 1
            updated = True

        # Now preprocess 'add-application': insert 'remove-application' if:
        # - there are applications to be removed
        # - the 'add-application' was found in requests
        #
        if application_params and indexes['add-application'] > -1:
            if indexes['remove-application'] == -1:
                # If list has no 'remove-application' at all just add it before 'add-applications'.
                idx = indexes['add-application']
                _insert_request(requests, idx, 'remove-application', application_params, updated)
            elif indexes['remove-application'] > indexes['add-application']:
                # If list has 'remove-application' after the 'add-applications',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-application' was found after 'add-application': NOT SUPPORTED")

        # Now preprocess 'add-multilink-policy': insert 'remove-multilink-policy' if:
        # - there are policies to be removed
        # - there are interfaces to be removed or to be added
        # - the 'add-multilink-policy' was found in requests
        #
        if multilink_policy_params and indexes['add-multilink-policy'] > -1:
            if indexes['remove-multilink-policy'] == -1:
                # If list has no 'remove-multilink-policy' at all just add it before 'add-multilink-policy'.
                idx = indexes['add-multilink-policy']
                _insert_request(requests, idx, 'remove-multilink-policy', multilink_policy_params, updated)
            elif indexes['remove-multilink-policy'] > indexes['add-multilink-policy']:
                # If list has 'remove-multilink-policy' after the 'add-multilink-policy',
                # it is not supported yet ;) Implement on demand
                raise Exception("_preprocess_request: 'remove-multilink-policy' was found after 'add-multilink-policy': NOT SUPPORTED")

        # Now preprocess 'add/remove-application' and 'add/remove-interface':
        # reinstall multilink policy if:
        # - any of 'add/remove-application', 'add/remove-interface' appears in request
        # - the original request does not have 'remove-multilink-policy'
        #
        if multilink_policy_params:
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

            # Now add policy reinstallation if needed.
            #
            if indexes['remove-multilink-policy'] > idx:
                # Move 'remove-multilink-policy' to the idx position:
                # insert it as the idx position and delete the original 'remove-multilink-policy'.
                idx_policy = indexes['remove-multilink-policy']
                _insert_request(requests, idx, 'remove-multilink-policy', multilink_policy_params, updated)
                del requests[idx_policy + 1]
            if indexes['add-multilink-policy'] > -1 and indexes['add-multilink-policy'] < idx_last:  # We exploit the fact that only one 'add-multilink-policy' is possible
                # Move 'add-multilink-policy' to the idx_last+1 position to be after all other 'add-X':
                # insert it at the idx_last position and delete the original 'add-multilink-policy'.
                idx_policy = indexes['add-multilink-policy']
                _insert_request(requests, idx_last+1, 'add-multilink-policy', multilink_policy_params, updated)
                del requests[idx_policy]
            if indexes['remove-multilink-policy'] == -1:
                _insert_request(requests, idx, 'remove-multilink-policy', multilink_policy_params, updated)
                idx_last += 1
            if indexes['add-multilink-policy'] == -1 and reinstall_multilink_policy:
                _insert_request(requests, idx_last+1, 'add-multilink-policy', multilink_policy_params, updated)

        if updated:
            fwglobals.log.debug("_preprocess_request: request was replaced with %s" % json.dumps(request))
        return request

    def _start_threads(self):
        """Start all threads.
        """
        if self.thread_watchdog is None:
            self.thread_watchdog = threading.Thread(target=self.watchdog, name='Watchdog Thread')
            self.thread_watchdog.start()
        if self.thread_tunnel_stats is None:
            self.thread_tunnel_stats = threading.Thread(target=self.tunnel_stats_thread, name='Tunnel Stats Thread')
            self.thread_tunnel_stats.start()
        if self.thread_dhcpc is None:
            self.thread_dhcpc = threading.Thread(target=self.dhcpc_thread, name='DHCP Client Thread')
            self.thread_dhcpc.start()
        if self.thread_ikev2 is None:
            self.thread_ikev2 = threading.Thread(target=self.ikev2_thread, name='IKEv2 Thread')
            self.thread_ikev2.start()

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

        if self.thread_ikev2:
            self.thread_ikev2.join()
            self.thread_ikev2 = None

    def _on_start_router_before(self):
        """Handles pre start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTING)

        # Reset sa-id used by tunnels
        #
        router_api_db = fwglobals.g.db['router_api']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        router_api_db['sa_id'] = 0
        fwglobals.g.db['router_api'] = router_api_db

        fwutils.vmxnet3_unassigned_interfaces_up()

        fwnetplan.load_netplan_filenames()


    def _on_start_router_after(self):
        """Handles post start VPP activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STARTED)
        self._start_threads()
        fwglobals.log.info("router was started: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _on_stop_router_before(self):
        """Handles pre-VPP stop activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STOPPING)
        self._stop_threads()
        fwutils.reset_dhcpd()
        fwglobals.g.cache.pci_to_vpp_tap_name = {}
        fwglobals.log.info("router is being stopped: vpp_pid=%s" % str(fwutils.vpp_pid()))

    def _on_stop_router_after(self):
        """Handles post-VPP stop activities.
        :returns: None.
        """
        self.state_change(FwRouterState.STOPPED)
        fwglobals.g.cache.pci_to_vpp_tap_name = {}

    def _on_apply_router_config(self):
        """Apply router configuration on successful VPP start.
        """
        types = [
            'add-interface',
            'add-tunnel',
            'add-application',
            'add-multilink-policy',
            'add-route',            # Routes should come after tunnels, as they might use them!
            'add-dhcp-config'
        ]
        messages = fwglobals.g.router_cfg.dump(types=types)
        for msg in messages:
            reply = fwglobals.g.router_api._call_simple(msg)
            if reply.get('ok', 1) == 0:  # Break and return error on failure of any request
                return reply


    # 'substitute' takes parameters in form of list or dictionary and
    # performs substitutions found in params.
    # Substitutions are kept in special element which is part of parameter list/dictionary.
    # When this function finishes to perform substitutions, it removes this element from params.
    # The substitution element is a dictionary with one key only - 'substs' and list
    # of substitutions as the value of this key: 
    #   { 'substs': [ {<subst1>} , {<subst2>} ... {<substN>} ] }
    # There are few types of substitutions:
    #   - substitution by function (see 'val_by_func' below)
    #   - substitution by value fetched from cache (see 'val_by_key' below)
    # As well 'substitute' function can
    #   - add new parameter to the original 'params' list/dictionary (see 'add_param' below)
    #   - go over all parameters found in 'params' and replace old value with new (see 'replace' below)
    # If function is used, the function argument can be
    #   - explicit value (see 'arg' below)
    #   - value fetched from cache (see 'arg_by_key' and 'val_by_key' below)
    #
    # That results in following format of single substitution element: 
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg'          : <input argument for 'val_by_func' function> 
    #   }
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg_by_key'   : <key to get the input argument for 'val_by_func' function from cache> 
    #   }
    #   {
    #       'add_param'    : <name of keyword parameter to be added. Used for dict parameters only>
    #       'val_by_key'   : <key to get the value of new parameter> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg'          : <input argument for 'val_by_func' function> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_func'  : <function that maps argument into value of new 'add_param' parameter. It should sit in fwutils module>
    #       'arg_by_key'   : <key to get the input argument for 'val_by_func' function from cache> 
    #   }
    #   {
    #       'replace'      : <substring to be replaced>
    #       'val_by_key'   : <key to get the value of new parameter> 
    #   }
    #
    # Once function finishes to handle all substitutions found in the 'substs' element,
    # it removes 'substs' element from the 'params' list/dictionary.
    #
    def _substitute(self, cache, params):
        """It takes parameters in form of list or dictionary and
        performs substitutions found in params.
        Once function finishes to handle all substitutions found in the 'substs' element,
        it removes 'substs' element from the 'params' list/dictionary.

        :param cache:          Cache.
        :param params:         Parameters.

        :returns: None.
        """
        if params is None:
            return

        # Perform substitutions in nested dictionaries and lists
        #
        if type(params)==list:
            for p in params:
                if type(p)==list or\
                (type(p)==dict and not 'substs' in p):  # Escape 'substs' element
                    self._substitute(cache, p)
        elif type(params)==dict:
            for item in params.items():
                key = item[0]
                p   = item[1]
                if (type(p)==dict or type(p)==list) and \
                key != 'substs':                       # Escape 'substs' element
                    self._substitute(cache, p)

        # Fetch list of substitutions
        substs = None
        if type(params)==dict and 'substs' in params:
            substs = params['substs']
        elif type(params)==list:
            for p in params:
                if type(p)==dict and 'substs' in p:
                    substs = p['substs']
                    substs_element = p
                    break
        if substs is None:
            return

        # Go over list of substitutions and perform each of them
        for s in substs:

            # Find the new value to be added to params
            if 'val_by_func' in s:
                func_name = s['val_by_func']
                func = getattr(fwutils, func_name)
                old  = s['arg'] if 'arg' in s else cache[s['arg_by_key']]
                new  = func(old)
                if new is None:
                    raise Exception("fwutils.py:substitute: %s failed to map %s in '%s'" % (func, old, format(params)))
            elif 'val_by_key' in s:
                new = cache[s['val_by_key']]
            else:
                raise Exception("fwutils.py:substitute: not supported type of substitution source in '%s'" % format(params))

            # Add new param/replace old value with new one
            if 'add_param' in s:
                if type(params) is dict:
                    if 'args' in params:        # Take care of cmd['cmd']['name'] = "python" commands
                        params['args'][s['add_param']] = new
                    else:                       # Take care of rest commands
                        params[s['add_param']] = new
                else:  # list
                    params.insert({s['add_param'], new})
            elif 'replace' in s:
                old = s['replace']
                if type(params) is dict:
                    raise Exception("fwutils.py:substitute: 'replace' is not supported for dictionary in '%s'" % format(params))
                else:  # list
                    for (idx, p) in enumerate(params):
                        if fwutils.is_str(p):
                            params.insert(idx, p.replace(old, new))
                            params.remove(p)
            else:
                raise Exception("fwutils.py.substitute: not supported type of substitution in '%s'" % format(params))

        # Once all substitutions are made, remove substitution list from params
        if type(params) is dict:
            del params['substs']
        else:  # list
            params.remove(substs_element)

