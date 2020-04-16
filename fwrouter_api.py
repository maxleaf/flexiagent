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
import os
import re
import time
import threading
import traceback
import yaml
import json

import fwglobals
import fwutils

from fwdb_requests import FwDbRequests
from fwapplications_api import FwApps
from fwmultilink import FwMultilink
from vpp_api import VPP_API

import fwtunnel_stats

import fwtranslate_add_tunnel
import fwtranslate_add_interface

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
    'start-router':               {'module':'fwtranslate_start_router',    'api':'start_router',      'key_func':'get_request_key'},
    'stop-router':                {'module':'fwtranslate_revert',          'api':'revert',            'src':'start-router'},
    'add-interface':              {'module':'fwtranslate_add_interface',   'api':'add_interface',     'key_func':'get_request_key'},
    'remove-interface':           {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-interface'},
    'add-route':                  {'module':'fwtranslate_add_route',       'api':'add_route',         'key_func':'get_request_key'},
    'remove-route':               {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-route'},
    'add-tunnel':                 {'module':'fwtranslate_add_tunnel',      'api':'add_tunnel',        'key_func':'get_request_key'},
    'remove-tunnel':              {'module':'fwtranslate_revert',          'api':'revert',            'src':'add-tunnel'},
    'add-dhcp-config':            {'module':'fwtranslate_add_dhcp_config', 'api':'add_dhcp_config',   'key_func':'get_request_key'},
    'remove-dhcp-config':         {'module':'fwtranslate_revert',          'api':'revert',            'src': 'add-dhcp-config'},
    'add-application':            {'module':'fwtranslate_add_app',         'api':'add_app',           'key_func':'get_request_key'},
    'remove-application':         {'module':'fwtranslate_revert',          'api': 'revert',           'src': 'add-application'},
    'add-multilink-policy':      {'module':'fwtranslate_add_policy',      'api': 'add_policy',       'key_func':'get_request_key'},
    'remove-multilink-policy':   {'module':'fwtranslate_revert',          'api': 'revert',           'src': 'add-multilink-policy'},
}

class FWROUTER_API:
    """This is Router API class representation.
    The Router API class provides control over vpp.
    That includes:
    - start and stop vpp functionality
    - wrappers for vpp configuration APIs
    - collecting statistics about vpp activity
    - monitoring vpp and restart it on exceptions
    - restoring vpp configuration on vpp restart or on device reboot

    :param request_db_file: Requests DB file name
    """
    def __init__(self, request_db_file, multilink_db_file):
        """Constructor method
        """
        self.vpp_api         = VPP_API()
        self.db_requests     = FwDbRequests(request_db_file)    # Database of executed requests
        self.multilink       = FwMultilink(multilink_db_file)
        self.router_started  = False
        self.router_failure  = False
        self.thread_watchdog = None
        self.thread_tunnel_stats = None

    def finalize(self):
        """Destructor method
        """
        self.vpp_api.finalize()
        self.db_requests.finalize()
        self.router_started = False
        self._stop_threads()

    def watchdog(self):
        """Watchdog thread.
        Its function is to monitor if VPP process is alive.
        Otherwise it will start VPP and restore configuration from DB.
        """
        while self.router_started:
            time.sleep(1)  # 1 sec
            try:           # Ensure watchdog thread doesn't exit on exception
                if not fwutils.vpp_does_run():      # This 'if' prevents debug print by restore_vpp_if_needed() every second
                    fwglobals.log.debug("watchdog: initiate restore")

                    self.vpp_api.disconnect()       # Reset connection to vpp to force connection renewal
                    restored = self.restore_vpp_if_needed()  # Rerun VPP and apply configuration

                    if not restored:                # If some magic happened and vpp is alive without restore, connect back to VPP
                        if fwutils.vpp_does_run():
                            fwglobals.log.debug("watchdog: vpp is alive with no restore!!! (pid=%s)" % str(fwutils.vpp_pid))
                            self.vpp_api.connect()
                        fwglobals.log.debug("watchdog: no need to restore")
                    else:
                        fwglobals.log.debug("watchdog: restore finished")
            except Exception as e:
                fwglobals.log.error("watchdog: exception: %s" % str(e))
                pass

    def tunnel_stats_thread(self):
        """Tunnel statistics thread.
        Its function is to monitor tunnel state and RTT.
        It is implemented by pinging the other end of the tunnel.
        """
        self._fill_tunnel_stats_dict()
        while self.router_started:
            time.sleep(1)  # 1 sec
            fwtunnel_stats.tunnel_stats_test()

    def restore_vpp_if_needed(self):
        """Restore VPP.
        If vpp doesn't run because of crash or device reboot,
        and it was started by management, start vpp and restore it's configuration.
        We do that by simulating 'start-router' request.
        Restore router state always to support multiple instances of Fwagent.

        :returns: `False` if no restore was performed, `True` otherwise.
        """
        self._restore_router_failure()

        # If vpp runs already, or if management didn't request to start it, return.
        vpp_runs = fwutils.vpp_does_run()
        vpp_should_be_started = self.db_requests.exists('start-router')
        if vpp_runs or not vpp_should_be_started:
            fwglobals.log.debug("restore_vpp_if_needed: no need to restore(vpp_runs=%s, vpp_should_be_started=%s)" %
                (str(vpp_runs), str(vpp_should_be_started)))
            self.router_started = vpp_runs
            if self.router_started:
                fwglobals.log.debug("restore_vpp_if_needed: vpp_pid=%s" % str(fwutils.vpp_pid()))
                self._start_threads()
            return False

        # Now start router.
        fwglobals.log.info("===restore vpp: started===")
        try:
            with FwApps(fwglobals.g.APP_REC_DB_FILE) as db_app_rec:
                db_app_rec.clean()
            with FwMultilink(fwglobals.g.MULTILINK_DB_FILE) as db_multilink:
                db_multilink.clean()

            fwglobals.g.handle_request('start-router', None)
        except Exception as e:
            fwglobals.log.excep("restore_vpp_if_needed: %s" % str(e))
            self._set_router_failure("failed to restore vpp configuration")
        fwglobals.log.info("====restore vpp: finished===")
        return True

    def start_router(self):
        """Execute start router command.
        """
        fwglobals.log.info("FWROUTER_API: start_router")
        if self.router_started == False:
            self.call('start-router')
        fwglobals.log.info("FWROUTER_API: start_router: started")

    def stop_router(self):
        """Execute stop router command.
        """
        fwglobals.log.info("FWROUTER_API: stop_router")
        if self.router_started == True:
            self.call('stop-router')
        fwglobals.log.info("FWROUTER_API: stop_router: stopped")

    def call(self, req, params={}):
        """Executes simple or aggregated request.
        The aggregated request is a request that consist of few simple requests.
        The simple request is a request that configure single parameter,
        like 'add-request', 'remove-router', etc.
        We support aggregation to save transactions betweens flexiManage and flexiEdge.

        :param req:         Request name.
        :param params:      Parameters from flexiManage.

        :returns: Status codes dictionary.
        """
        # modify-device requests are split into their corresponding remove/add requests.
        # This code should be replaced with a true modify operation that performs
        # the change in-place, without removing and adding the interface.
        if req == 'modify-device':
            return self._handle_modify_device_request(params)

        # Router configuration requests might unite multiple requests of same type
        # arranged into list, e.g. 'add-interface' : [ {iface1}, {iface2}, ...].
        # To handle that we split that kinds of requests into multiple simple requests,
        # as they would be received over network, and execute them one by one.
        if re.match('add-|remove-', req) and type(params) is list:
            requests = [{req: param} for param in params]
            return self._call_aggregated(requests)
        else:
            return self._call_simple(req, params)

    def _call_aggregated(self, requests):
        """Execute multiple requests.
        It do that as an atomic operation,
        i.e. if one of requests fails, all the previous are reverted.

        :param requests:         Request list.

        :returns: Status codes dictionary.
        """
        # Go over all remove-* requests and replace their parameters
        # with parameters of the corresponding add-* requests that are stored in request database.
        # Usually the remove-* request has only partial set of parameters
        # received with correspondent add-* request. That makes it impossible
        # to revert remove-* request if one of the subsequent requests
        # in the aggregated request fails and as a result of this whole aggregated request is rollback-ed.
        # For example, 'remove-interface' has 'pci' parameter only, and has no IP, LAN/WAN type, etc.
        fwglobals.log.debug("FWROUTER_API: === start handling aggregated request ===")
        for req in requests:
            try:
                (op, params), = req.items()
                if re.match('remove-', op):
                    req[op] = self._get_request_params_from_db(op, params)

            except Exception as e:
                fwglobals.log.excep("_call_aggregated: failed to fetch params for %s: %s " % (json.dumps(req), str(e)))
                raise e


        for (idx, req) in enumerate(requests):
            try:
                (op, params), = req.items()
                fwglobals.log.debug("_call_aggregated: executing request %s with params %s" % (op, json.dumps(req)))
                self._call_simple(op, params)
            except Exception as e:
                # Revert previously succeeded simple requests
                fwglobals.log.error("_call_aggregated: failed to execute %s. reverting previous requests..." % json.dumps(req))
                for rev_req in reversed(requests[0:idx]):
                    try:
                        (orig_op, orig_params), = rev_req.items()
                        rev_op = orig_op.replace('add-','remove-') if re.match('add-', orig_op) else orig_op.replace('remove-','add-')
                        self._call_simple(rev_op, orig_params)
                    except Exception as er:
                        # on failure to revert move router into failed state
                        fwglobals.log.excep(
                            "failed to revert request %s while running rollback on aggregated request(%s): %s" % \
                            (orig_op, format(orig_params), format(er)))
                        self._set_router_failure("failed to revert request %s while running rollback on aggregated request" % orig_op)
                        pass
                raise

        fwglobals.log.debug("FWROUTER_API: === end handling aggregated request ===")
        return {'ok':1}

    def _extract_request_key(self, req, params):
        src_req      = fwrouter_translators[req]['src']
        src_module   = fwrouter_modules.get(fwrouter_translators[src_req]['module'])
        src_key_func = getattr(src_module, fwrouter_translators[src_req]['key_func'])
        src_req_key  = src_key_func(params)
        return src_req_key

    def _get_request_params_from_db(self, req, params):
        """Retrives parameters from DB by key, generated out of provided request.
        This function is needed to handle 'remove-X' requests, e.g. 'remove-tunnel'.
        Parameters of the X object are stored in the DB when the matching 'add-X' request is handled.
        Note 'add-X' and 'remove-X' requests have same key.
        """
        request_key = self._extract_request_key(req, params)
        return self.db_requests.fetch_request(request_key)[1]

    def _fill_tunnel_stats_dict(self):
        """Get tunnels their corresponding loopbacks ip addresses
        to be used by tunnel statistics thread.
        """
        fwtunnel_stats.tunnel_stats_clear()
        for key, request in self.db_requests.db.items():
            if not re.search('add-tunnel', key):
                continue
            id = request['params']['tunnel-id']
            addr = request['params']['loopback-iface']['addr']
            fwtunnel_stats.tunnel_stats_add(id, addr)

    def refresh_policies(self):
        params = dict()
        params['modify_policy'] = {}
        params['modify_policy']['policies'] = []

        for key, request in self.db_requests.db.items():
            if re.search('add-multilink-policy', key):
                params['modify_policy']['policies'].append(request['params'])

        self.call('modify-device', params)

    def _need_to_translate(self, req):
        if re.search('-app',  req):
            return False

        if re.search('-policy',  req):
            return False

        return True

    def _call_simple(self, req, params):
        """Execute request.

        :param req:         Request name.
        :param params:      Request parameters.

        :returns: Status codes dictionary.
        """
        # 'start-router', 'stop-router' and 'reset-router' have special handling,
        # as they deal with watchdog thread, applying configuration on start, etc.
        # All the rest of requests are handled in common way.
        if re.search('-router',  req):
            if req == 'start-router':
                self._start_router(req, params)
            elif req == 'stop-router':
                self._stop_router(req, params)
            else: #if req == 'reset-router':
                fwutils.reset_router_config()
            return {'ok':1}

        # If device failed, which means it is in not well defined state,
        # reject request immediately as it can't be fulfilled.
        # Permit configuration requests only ('add-XXX' & 'remove-XXX')
        # in order to enable management to fix configuration.
        if self._test_router_failure() and not re.match('add-|remove-',  req):
            raise Exception("device failed, can't fulfill requests")

        # Translate request to list of commands to be executed
        if self._need_to_translate(req):
            (cmd_list , req_key , complement) = self._translate(req, params)
        else:
            (cmd_list, req_key, complement) = self._translate(req, params, False)

        # Execute commands only if vpp runs.
        # Some 'remove-XXX' requests must be executed
        # even if vpp doesn't run right now. This is to clean stuff in Linux
        # that was added by correspondent 'add-XXX' request if the last was
        # applied to running vpp.
        router_was_started = fwutils.vpp_does_run()
        executed = False
        if router_was_started or re.match('remove-',  req):
            filter = 'must' if not router_was_started else None
            self._execute(req, req_key, cmd_list, filter)
            executed = True

        # Save translation of succeeded request for future use by complement requests
        # e.g. 'remove-tunnel', or remove source request if the complement request
        # has been executed.
        self._update_db_requests(complement, req_key, req, params, cmd_list, executed)

        if re.match('(add|remove)-tunnel',  req):
            self._fill_tunnel_stats_dict()

        return {'ok':1}


    def _translate(self, req, params=None, get_cmd_list=True):
        """Translate request in a series of commands.

        :param req:         Request name.
        :param params:      Request parameters.

        :returns: Status codes dictionary.
        """
        cmd_list = []
        api_defs = fwrouter_translators.get(req)
        assert api_defs, 'FWROUTER_API: there is no api for request "' + req + '"'

        module = fwrouter_modules.get(fwrouter_translators[req]['module'])
        assert module, 'FWROUTER_API: there is no module for request "' + req + '"'

        func = getattr(module, fwrouter_translators[req]['api'])
        assert func, 'FWROUTER_API: there is no api function for request "' + req + '"'

        # All revert kind of API-s are handled by same function
        if fwrouter_translators[req]['api'] == 'revert':
            try:
                src_req_key = self._extract_request_key(req, params)
                if get_cmd_list:
                    cmd_list = func(src_req_key)
                return (cmd_list , src_req_key , True)   # True stands for reverting requests, like stop-router, remove-tunnel, etc.
            except KeyError as e:
                pass

        # Handle all the rest but revert requests
        request_key_func = getattr(module, fwrouter_translators[req]['key_func'])
        if params:
            if get_cmd_list:
                cmd_list    = func(params)
            request_key = request_key_func(params)
        else:
            if get_cmd_list:
                cmd_list    = func()
            request_key = request_key_func()
        return (cmd_list, request_key, False)     # False stands for initiating requests, like start-router, add-tunnel, etc.

    def _execute(self, req, req_key, cmd_list, filter=None):
        """Execute request.

        :param req:         Request name.
        :param req_key:     Request key.
        :param cmd_list:    Commands list.
        :param filter:      Filter.

        :returns: None.
        """
        cmd_cache = {}

        fwglobals.log.debug("FWROUTER_API: === start execution of %s (key=%s) ===" % (req, req_key))

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If precondition exists, ensure that it is OK
            if 'precondition' in t:
                precondition = t['precondition']
                reply = fwglobals.g.handle_request(precondition['name'], precondition.get('params'), result)
                if reply['ok'] == 0:
                    fwglobals.log.debug("FWROUTER_API:_execute: %s: escape as precondition is not met: %s" % (cmd['descr'], precondition['descr']))
                    continue

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    fwglobals.log.debug("FWROUTER_API:_execute: filter out command by filter=%s (req=%s, req_key=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
                                        (filter, req, req_key, cmd['name'], str(cmd.get('filter')), str(cmd.get('params'))))
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
                reply = fwglobals.g.handle_request(cmd['name'], cmd.get('params'), result)
                if reply['ok'] == 0:        # On failure go back revert already executed commands
                    fwglobals.log.debug("FWROUTER_API: %s failed ('ok' is 0)" % cmd['name'])
                    raise Exception("API failed: %s" % reply['message'])

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['name'], format(cmd.get('params')), str(e), traceback.format_exc())
                fwglobals.log.error(err_str)
                fwglobals.log.debug("FWROUTER_API: === failed execution of %s (key=%s) ===" % (req, req_key))
                # On failure go back to the begining of list and revert executed commands.
                self._revert(cmd_list, idx)
                fwglobals.log.debug("FWROUTER_API: === finished revert of %s (key=%s) ===" % (req, req_key))
                raise Exception('failed to ' + cmd['descr'])

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self._substitute(cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    fwglobals.log.excep("_execute: failed to substitute revert command: %s, %s" % \
                                (str(e), traceback.format_exc()))
                    fwglobals.log.debug("FWROUTER_API: === failed execution of %s (key=%s) ===" % (req, req_key))
                    self._revert(cmd_list, idx)
                    raise e

        fwglobals.log.debug("FWROUTER_API: === end execution of %s (key=%s) ===" % (req, req_key))

    def _revert(self, cmd_list, idx_failed_cmd=-1):
        """Revert commands.

        :param cmd_list:            Commands list.
        :param idx_failed_cmd:      The last command index to be reverted.

        :returns: None.
        """
        if idx_failed_cmd != 0:
            for t in reversed(cmd_list[0:idx_failed_cmd]):
                if 'revert' in t:
                    rev_cmd = t['revert']
                    try:
                        reply = fwglobals.g.handle_request(rev_cmd['name'], rev_cmd.get('params'))
                        if reply['ok'] == 0:
                            err_str = "handle_request(%s) failed" % rev_cmd['name']
                            fwglobals.log.error(err_str)
                            raise Exception(err_str)
                    except Exception as e:
                        err_str = "_revert: exception while '%s': %s(%s): %s" % \
                                    (t['cmd']['descr'], rev_cmd['name'], format(rev_cmd['params']), str(e))
                        fwglobals.log.excep(err_str)
                        self._set_router_failure("_revert: failed to revert '%s'" % t['cmd']['descr'])


    def _update_db_requests(self, complement, req_key, request, params, cmd_list, executed=True):
        """Update requests in DB.

        :param complement:          Remove from DB if equals to 'True', otherwise add into DB.
        :param req_key:             Request key.
        :param request:             Request name.
        :param params:              Request parameters.
        :param cmd_list:            Commands list.
        :param executed:            Executed flag.

        :returns: None.
        """
        try:
            if complement:
                self.db_requests.remove(req_key)
            else:
                self.db_requests.add(req_key, request, params, cmd_list, executed)
        except KeyError as e:
            pass
        except Exception as e:
            fwglobals.log.error("_update_db_requests(%s,%s) failed: %s, %s" % \
                        (format(complement), req_key, str(e), traceback.format_exc()))
            self._revert(cmd_list)
            raise Exception('failed to update request database')

    def _start_threads(self):
        """Start all threads.
        """
        if self.thread_watchdog is None:
            self.thread_watchdog = threading.Thread(target=self.watchdog, name='Watchdog Thread')
            self.thread_watchdog.start()
        if self.thread_tunnel_stats is None:
            self.thread_tunnel_stats = threading.Thread(target=self.tunnel_stats_thread, name='Tunnel Stats Thread')
            self.thread_tunnel_stats.start()

    def _stop_threads(self):
        """Stop all threads.
        """
        if self.thread_watchdog:
            self.thread_watchdog.join()
            self.thread_watchdog = None

        if self.thread_tunnel_stats:
            self.thread_tunnel_stats.join()
            self.thread_tunnel_stats = None

    def _start_router(self, req, params):
        """Start and configure VPP.

        :param req:             start-router request.
        :param params:          Request parameters.

        :returns: None.
        """
        # cleanup of globals in tunnels
        fwtranslate_add_tunnel.init_tunnels()

        # 'start-router' preprocessing:
        # the 'start-router' request might include interfaces and routes.
        # For each of them simulate 'add-interface' and 'add-route' request
        # as they would be received from management. This is to enable
        # management to remove them one by one if needed.
        if params:
            try:
                if 'interfaces' in params:
                    fwglobals.g.handle_request('add-interface', params['interfaces'])
                    del params['interfaces']
                if 'routes' in params:
                    fwglobals.g.handle_request('add-route', params['routes'])
                    del params['routes']
                if bool(params) == False:
                    params = None
            except Exception as e:
                err_str = "_start_router: failure to simulate requests: %s" % traceback.format_exc()
                fwglobals.log.error(err_str)
                self._set_router_failure("failed to simulate add-interface or add-route requests")
                raise e

        # Now process the 'start-router' request
        (cmd_list , req_key , complement) = self._translate(req, params)
        self._execute(req, req_key, cmd_list)
        try:
            self._apply_router_config()
            # Store succeeded 'start-router' request in DB.
            new_params = {} if not params else copy.deepcopy(params)
            cmd_list = [cmd for cmd in cmd_list if cmd['cmd']['name'] != "handle-request"]
            self._update_db_requests(complement, req_key, req, new_params, cmd_list)
        except Exception as e:
            err_str = "_start_router: %s" % traceback.format_exc()
            fwglobals.log.error(err_str)
            self._revert(cmd_list)
            self._set_router_failure("failed to apply configuration on router start")
            raise e

        # On successful start reset the failure mark and
        # run the watchdog thread, if it doesn't run
        self.router_started = True
        self._start_threads()
        self._unset_router_failure()
        fwglobals.log.info("router was started: vpp_pid=%s" % str(fwutils.vpp_pid()))


    def _stop_router(self, req, params):
        """Stop VPP.

        :param req:             stop-router request.
        :param params:          Request parameters.

        :returns: None.
        """
        # Firstly stop the watchdog thread to avoid race
        # on restoring vpp by it, when the current thread stops vpp on purpose 
        self.router_started = False 
        self._stop_threads()
        fwutils.reset_dhcpd()

        # Now translate and execute stop-router.
        # On any problem we have to force router stop,
        # so we handle exceptions here
        try:
            (cmd_list , req_key , complement) = self._translate(req, params)
            self._execute(req, req_key, cmd_list)
            self._update_db_requests(complement, req_key, req, params, cmd_list)
            fwglobals.log.info("vRouter was stopped")
        except Exception as e:
            err_str = "_stop_router: failed to stop gracefully: %s, %s" % (str(e), traceback.format_exc())
            fwglobals.log.excep(err_str)
            fwutils.stop_router()
            self._set_router_failure("failed to stop router gracefully")
            raise e

    def _create_remove_tunnels_request(self, params):
        """Creates a list of remove-tunnel requests for all tunnels
           that are connected to interfaces that are either modified
           or unassigned.

        :param params:          modify-device request parameters.

        :returns: Array of remove-tunnel requests.
        """

        # Get the pci address of all changed interfaces
        interfaces = [] if 'modify_router' not in params else params['modify_router'].get('unassign', [])
        interfaces += [] if 'modify_interfaces' not in params else params['modify_interfaces'].get('interfaces', [])
        pci_set = set(map(lambda interface: interface['pci'], interfaces))
        ip_set = set()

        # Create a set of the IP addresses that correspond to each PCI.
        for pci in pci_set:
            try:
                key = fwtranslate_add_interface.get_request_key({'pci': pci})
                (req, entry) = self.db_requests.fetch_request(key)
                if entry != None:
                    ip_set.add(entry['addr'].split('/')[0])

            except Exception as e:
                fwglobals.log.excep("failed to create remove-tunnel requests list %s" % str(e))
                raise e

        # Go over all tunnels in the database and add every tunnel
        # which src field exists in the IP addresses set
        tunnels_requests = []
        for key in self.db_requests.db:
            try:
                if re.match('add-tunnel', key):
                    (req, entry) = self.db_requests.fetch_request(key)
                    if entry['src'] in ip_set:
                        tunnels_requests.append({'remove-tunnel': {'tunnel-id': entry['tunnel-id']}})
            except Exception as e:
                fwglobals.log.excep("failed to create remove-tunnel requests list %s" % str(e))
                raise e

        return tunnels_requests

    def _handle_modify_device_request(self, params):
        """Handle modify_routes, modify_interfaces or modify_router request.

        :param params:          Request parameters.

        :returns: Status code.
        """
        requests = []
        interfaces = []
        should_restart_router = False

        # First, create a list of remove-tunnel requests to remove
        # all tunnels that are connected to the modified interfaces.
        # These tunnels must be removed before modifying the interface
        # and will be added back (if needed) via a message from the MGMT.
        if 'modify_interfaces' in params or 'modify_router' in params:
            requests += self._create_remove_tunnels_request(params)
        if 'modify_routes' in params:
            requests += self._create_modify_routes_request(params['modify_routes'])
        if 'modify_interfaces' in params:
            interfaces = params['modify_interfaces']['interfaces']
            requests += self._create_modify_interfaces_request(params['modify_interfaces'])
        if 'modify_router' in params:
            # Changing the 'assigned' field of an interface requires router
            # restart. Only restart if the router is currently running.
            should_restart_router = self.router_started
            requests += self._create_modify_router_request(params['modify_router'])
        if 'modify_dhcp_config' in params:
            requests += self._create_modify_dhcp_config_request(params['modify_dhcp_config'])
        if 'modify_app' in params:
            requests += self._create_modify_app_request(params['modify_app'])
        if 'modify_policy' in params:
            requests += self._create_modify_policy_request(params['modify_policy'])

        try:
            if should_restart_router == True:
                self._stop_router("stop-router", {})

            self._call_aggregated(requests)

            if should_restart_router == True:
                self._start_router("start-router", {})
        except Exception as e:
                fwglobals.log.excep("_modify_device: %s" % str(e))
                raise e

        # Modifying interfaces might result in removal of static routes,
        # which can affect the agent's ability to reconnect to the MGMT
        # (if default route or any other route the agent uses to connect to
        # the MGMT was removed). In order to overcome this, we try to restore
        # the lost routes. Since this is a best effort solution, we don't return
        # error if we fail to restore a route.
        changed_ips = map(lambda interface: interface['addr'], interfaces)
        if len(changed_ips) > 0:
            for key in self.db_requests.db:
                try:
                    if re.match('add-route', key):
                        next_hop_ip = self.db_requests.db[key]['params']['via']
                        if(any([fwutils.is_ip_in_subnet(next_hop_ip, subnet) for subnet in changed_ips])):
                            fwglobals.log.info('restoring static route: ' + str(key))
                            self._apply_db_request(key)
                except Exception as e:
                    fwglobals.log.excep("_modify_device: failed to restore static routes %s" % str(e))
                    pass

        return {'ok':1}

    def _create_modify_interfaces_request(self, params):
        """'modify-interface' pre-processing:
        This command is a wrapper around the 'add-interface' and 'remove-interface' commands.
        To modify the interface we simply remove the interface and add the it with the new configuration.

        :param params:          Request parameters.

        :returns: Array of requests.
        """
        modify_interface_requests = []

        if params:
            for interface in params['interfaces']:
                # Remove interface only if it exists in the database
                if self._get_request_params_from_db('remove-interface', interface):
                    modify_interface_requests.append({'remove-interface': interface})
                modify_interface_requests.append({'add-interface': interface})

        return modify_interface_requests

    def _create_modify_routes_request(self, params):
        """'modify-route' pre-processing:
        This command is a wrapper around the 'add-route' and 'remove-route' commands.
        To modify the route we simply remove the old route and add the new one.

        :param params:          Request parameters.

        :returns: Array of requests.
        """
        modify_route_requests = []
        if params:
            for route in params['routes']:
                remove_route_params = {}
                add_route_params = {}
                
                # Modified routes will have both the 'old_route' and 'new_route'
                # fields, whereas added/removed routes will only have the 'new_route'
                # or 'old_route' fields.
                if route['old_route'] != '':
                    remove_route_params = {k:v for k,v in route.items() if k not in ['new_route']}
                    remove_route_params['via'] = remove_route_params.pop('old_route')
                    # Remove route only if it exists in the database
                    if self._get_request_params_from_db('remove-route', remove_route_params):
                        modify_route_requests.append({'remove-route': remove_route_params})

                if route['new_route'] != '':
                    add_route_params = {k:v for k,v in route.items() if k not in ['old_route']}
                    add_route_params['via'] = add_route_params.pop('new_route')
                    modify_route_requests.append({'add-route': add_route_params})
                
        return modify_route_requests

    def _create_modify_router_request(self, params):
        """This command handles the transition of an interface from
        assigned to unassigned and vice versa. If an interface becomes
        assigned, it should be added to the router configuration.
        If an interface becomes unassigned, it should be removed.
        The router has to ber restarted after this operation.

        :param params:          Request parameters.

        :returns: Array of requests.
        """
        modify_router_requests = []
        if params:
            if 'unassign' in params:
                for ifc in params['unassign']:
                    # Remove interface only if it exists in the database
                    if self._get_request_params_from_db('remove-interface', ifc):
                        modify_router_requests.append({'remove-interface': ifc})
            if 'assign' in params:
                for ifc in params['assign']:
                    modify_router_requests.append({'add-interface': ifc})

        return modify_router_requests

    def _create_modify_dhcp_config_request(self, params):
        """'modify_dhcp_config' pre-processing:
        This command is a wrapper around the 'add-dhcp-config' and 'remove-dhcp-config' commands.

        :param params:          Request parameters.

        :returns: Array of requests.
        """
        modify_requests = []

        if params:
            for config in params['dhcp_configs']:
                # Remove dhcp config only if it exists in the database
                if self._get_request_params_from_db('remove-dhcp-config', config):
                    modify_requests.append({'remove-dhcp-config': config})
                modify_requests.append({'add-dhcp-config': config})

        return modify_requests

    def _create_modify_policy_request(self, params):
        """'modify_policy' pre-processing:
        This command is a wrapper around the 'add-multilink-policy' and 'remove-multilink-policy' commands.

        :param params:          Request parameters.

        :returns: Array of requests.
            """

        modify_requests = []

        if params:
            for policy in params['policies']:
                # Remove policy only if it exists in the database
                if self._get_request_params_from_db('remove-multilink-policy', policy):
                    modify_requests.append({'remove-multilink-policy': policy})
                modify_requests.append({'add-multilink-policy': policy})

        return modify_requests

    def _create_modify_app_request(self, params):
        """'modify_app' pre-processing:
        This command is a wrapper around the 'add-application' and 'remove-application' commands.

        :param params:          Request parameters.

        :returns: Array of requests.
        """
        modify_requests = []

        if params:
            for app in params['apps']:
                # Remove app only if it exists in the database
                if self._get_request_params_from_db('remove-application', app):
                    modify_requests.append({'remove-application': app})
                modify_requests.append({'add-application': app})

        return modify_requests

    def _set_router_failure(self, err_str):
        """Set router failure state.

        :param err_str:          Error string.

        :returns: None.
        """
        if not self.router_failure:
            self.router_failure = True
            if not os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                with open(fwglobals.g.ROUTER_STATE_FILE, 'w') as f:
                    if fwutils.valid_message_string(err_str):
                        f.write(err_str)
                    else:
                        fwglobals.log.excep("Not valid router failure reason string: '%s'" % err_str)
            fwutils.stop_router()

    def _unset_router_failure(self):
        """Unset router failure state.

        :returns: None.
        """
        if self.router_failure:
            self.router_failure = False
            if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
                os.remove(fwglobals.g.ROUTER_STATE_FILE)

    def _test_router_failure(self):
        """Get router failure state.

        :returns: 'True' if router is in failed state and 'False' otherwise.
        """
        return self.router_failure

    def _restore_router_failure(self):
        """Restore router failure state.

        :returns: None.
        """
        self.router_failure = True if os.path.exists(fwglobals.g.ROUTER_STATE_FILE) else False
        if self.router_failure:
            fwglobals.log.excep("router is in failed state, use 'fwagent reset [--soft]' to recover if needed")

    def _apply_router_config(self):
        """Apply router configuration.

        :returns: None.
        """
        try:
            # Firstly configure interfaces
            for key in self.db_requests.db:
                if re.match('add-interface', key):
                    self._apply_db_request(key)

            # Configure tunnels
            for key in self.db_requests.db:
                if re.match('add-tunnel', key):
                    self._apply_db_request(key)
                    self._fill_tunnel_stats_dict()

            # Configure apps
            for key in self.db_requests.db:
                if re.match('add-application', key):
                    self._apply_db_request(key)

            # Configure policies
            for key in self.db_requests.db:
                if re.match('add-multilink-policy', key):
                    self._apply_db_request(key)

            # Configure routes
            # Do that after routes, as routes might use tunnels!
            for key in self.db_requests.db:
                if re.match('add-route', key):
                    self._apply_db_request(key)

            # Configure dhcp server
            for key in self.db_requests.db:
                if re.match('add-dhcp-config', key):
                    self._apply_db_request(key)

        except Exception as e:
            err_str = "_apply_router_config failed: %s" % str(e)
            fwglobals.log.excep(err_str)
            raise e

    def _apply_db_request(self, key):
        """Apply DB request.

        :param key:          Request key.

        :returns: None.
        """
        (req, params) = self.db_requests.fetch_request(key)
        (cmd_list,_,_) = self._translate(req, params)
        self._execute(req, key, cmd_list)
        try:
            self.db_requests.update(key, req, params, cmd_list, executed=True)
        except Exception as e:
            fwglobals.log.error("_apply_router_config: failed to update DB: %s" % str(e))
            self._revert(cmd_list)
            raise e

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

    def get_default_route_address(self):
        for key, request in self.db_requests.db.items():
            if re.search('add-route:default', key):
                return request['params']['via']

    def get_pci_lan_interfaces(self):
        interfaces = []
        for key, request in self.db_requests.db.items():
            if re.search('add-interface', key):
                if re.match('lan', request['params']['type']):
                    interfaces.append(request['params']['pci'])

        return interfaces
