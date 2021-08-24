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

import fwglobals
import fwutils
import traceback
import json
import re

class FwCfgRequestHandler:
    """This is Request Handler class representation.
    The RequestHandler class enables user to execute requests received from flexiManage.
    To do that it provides following steps:
    1. Translates request into list of commands to be executed.
       This stage is called translation.
    2. Executes commands out of the translation list one by one.
       This stage is called execution.
       On failure to execute any of commands, the previously executed commands are reverted
       in order to rollback system to the state where it was before request receiving.
    3. Updates the persistent database with request result:
       for 'add-X' and 'modify-X' requests stores the request and it's translation into database,
       for 'remove-X' request deletes the stored request and translation from the database.
    Note these stages are exposed as module API-s to enable user to override the default behavior.

    In addition the Request Handler provides following functionality:
    1. Handle aggregated requests
    2. Implement sync and full sync logic
    """

    def __init__(self, translators, cfg_db, revert_failure_callback = None):
        """Constructor method.
        """
        self.translators = translators
        self.cfg_db = cfg_db
        self.revert_failure_callback = revert_failure_callback
        self.log                     = fwglobals.log

        self.cfg_db.set_translators(translators)

    def __enter__(self):
        return self

    def set_logger(self, logger=None):
        if self.log != logger:
            new_logger = logger if logger else fwglobals.log
            self.cfg_db.set_logger(new_logger)
            self.log = new_logger
            new_logger.debug("logging switched back from %s ..." % str(logger))

    def set_request_logger(self, request):
        old_logger = self.log
        new_logger = fwglobals.g.loggers.get(request['message'], fwglobals.log)
        if old_logger != new_logger:
            self.cfg_db.set_logger(new_logger)
            self.log = new_logger
            old_logger.debug("logging switched to %s ..." % str(new_logger))
        return old_logger

    def call(self, request, dont_revert_on_failure=False):
        if request['message'] == 'aggregated':
            reply = self._call_aggregated(request['params']['requests'], dont_revert_on_failure)
        else:
            reply = self._call_simple(request)
        return reply

    def rollback(self, request):
        try:
            self.call(request, dont_revert_on_failure=True) # True: Prevent revert of rollback :)
        except Exception as e:
            err_str = "rollback: failed for '%s': %s" % (request['message'], str(e))
            self.log.excep(err_str)
            if self.revert_failure_callback:
                self.revert_failure_callback(err_str)

    def _call_simple(self, request, execute=True, filter=None):
        """Execute single request.

        :param request: The request received from flexiManage.

        :returns: dictionary with status code and optional error message.
        """
        whitelist = None
        prev_logger = self.set_request_logger(request)   # Use request specific logger (this is to offload heavy 'add-application' logging)
        try:
            # Translate request to list of commands to be executed
            if re.match('modify-', request['message']):
                cmd_list, whitelist = self._translate_modify(request)
            else:
                cmd_list = self._translate(request)

            # Execute list of commands. Do it only if vpp runs.
            # Some 'remove-XXX' requests must be executed
            # even if vpp doesn't run right now. This is to clean stuff in Linux
            # that was added by correspondent 'add-XXX' request if the last was
            # applied to running vpp.
            if execute:
                self._execute(request, cmd_list, filter)

            # Save successfully handled configuration request into database.
            # We need it and it's translation to execute future 'remove-X'
            # requests as they are generated by reverting of correspondent
            # 'add-X' translations from last to the first. As well they are
            # needed to restore VPP configuration on device reboot or start of
            # crashed VPP by watchdog.
            try:
                self.cfg_db.update(request, cmd_list, execute, whitelist)
            except Exception as e:
                self._revert(cmd_list)
                self.set_logger(prev_logger)
                raise e
        except Exception as e:
            err_str = "_call_simple: %s" % str(traceback.format_exc())
            self.log.error(err_str)
            self.set_logger(prev_logger)
            raise e

        self.set_logger(prev_logger)
        return {'ok':1}

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

        :returns: dictionary with status code and optional error message.
        """
        self.log.debug("=== start handling aggregated request ===")

        for (idx, request) in enumerate(requests):

            # Don't print too large requests, if needed check print on request receiving
            #
            str_request = json.dumps(request)
            str_request = (str_request[:1000] + '..') if len(str_request) > 1000 else str_request

            try:
                self.log.debug("_call_aggregated: handle request %s" % str_request)
                self._call_simple(request)
            except Exception as e:
                if dont_revert_on_failure:
                    raise e
                # Revert previously succeeded simple requests
                self.log.error("_call_aggregated: failed to handle %s. reverting previous requests..." % str_request)
                for request in reversed(requests[0:idx]):
                    try:
                        op = request['message']
                        request['message'] = op.replace('add-','remove-') if re.match('add-', op) else op.replace('remove-','add-')
                        self._call_simple(request)
                    except Exception as e:
                        # on failure to revert move router into failed state
                        err_str = "_call_aggregated: failed to revert request %s while running rollback on aggregated request" % op
                        self.log.excep("%s: %s" % (err_str, format(e)))
                        if self.revert_failure_callback:
                            self.revert_failure_callback(t)
                        pass
                raise e

        self.log.debug("=== end handling aggregated request ===")
        return {'ok':1}

    def _translate(self, request):
        """Translate request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        req    = request['message']
        params = request.get('params')

        api_defs = self.translators.get(req)
        assert api_defs, 'there is no api for request "%s"' % req

        module = api_defs.get('module')
        assert module, 'there is no module for request "%s"' % req

        api = api_defs.get('api')
        assert api, 'there is no api for request "%s"' % req

        func = getattr(module, api)
        assert func, 'there is no api function for request "%s"' % req

        if api == 'revert':
            cmd_list = func(request, self.cfg_db)
            return cmd_list

        cmd_list = func(params) if params else func()
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

        self.log.debug("=== start execution of %s ===" % (req))

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    self.log.debug("_execute: filter out command by filter=%s (req=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
                                        (filter, req, cmd['name'], str(cmd.get('filter')), str(cmd.get('params'))))
                    continue

            try:
                # Firstly perform substitutions if needed.
                # The params might include 'substs' key with list of substitutions.
                self.substitute(cmd_cache, cmd.get('params'))

                if 'params' in cmd and type(cmd['params'])==dict:
                    params = fwutils.yaml_dump(cmd['params'])
                elif 'params' in cmd:
                    params = format(cmd['params'])
                else:
                    params = ''
                self.log.debug("_execute: %s(%s)" % (cmd['name'], params))

                # Now execute command
                result = None if not 'cache_ret_val' in cmd else \
                    { 'result_attr' : cmd['cache_ret_val'][0] , 'cache' : cmd_cache , 'key' :  cmd['cache_ret_val'][1] }
                reply = fwglobals.g.handle_request({ 'message': cmd['name'], 'params':  cmd.get('params')}, result)
                if reply['ok'] == 0:        # On failure go back revert already executed commands
                    self.log.debug("%s failed ('ok' is 0)" % cmd['name'])
                    raise Exception("API failed: %s" % cmd['name'])

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['name'], format(cmd.get('params')), str(e), str(traceback.format_exc()))
                self.log.error(err_str)
                self.log.debug("=== failed execution of %s ===" % (req))
                if fwglobals.g.router_api.state_is_starting_stopping():
                    fwutils.dump()
                # On failure go back to the begining of list and revert executed commands.
                self._revert(cmd_list, idx)
                self.log.debug("=== finished revert of %s ===" % (req))
                raise Exception('failed to %s. (error: %s)' % (cmd['descr'], str(e)))

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self.substitute(cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    self.log.excep("_execute: failed to substitute revert command: %s\n%s, %s" % \
                                (str(t), str(e), str(traceback.format_exc())))
                    self.log.debug("=== failed execution of %s ===" % (req))
                    self._revert(cmd_list, idx)
                    raise e

        self.log.debug("=== end execution of %s ===" % (req))

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
                        self.log.error(err_str)
                        raise Exception(err_str)
                except Exception as e:
                    err_str = "_revert: exception while '%s': %s(%s): %s" % \
                                (t['cmd']['descr'], rev_cmd['name'], format(rev_cmd['params']), str(e))
                    self.log.excep(err_str)

                    if self.revert_failure_callback:
                        self.revert_failure_callback(err_str)

                    return   # Don't continue, system is in undefined state now!


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
    def substitute(self, cache, params):
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
                    self.substitute(cache, p)
        elif type(params)==dict:
            for item in list(params.items()):
                key = item[0]
                p   = item[1]
                if (type(p)==dict or type(p)==list) and \
                key != 'substs':                       # Escape 'substs' element
                    self.substitute(cache, p)

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
                module , func_name = fwutils , s['val_by_func']
                if '.' in func_name:
                    module_name, func_name = func_name.split('.', 1)
                    module = __import__(module_name)

                func = getattr(module, func_name)
                old  = s['arg'] if 'arg' in s else cache[s['arg_by_key']]
                func_uses_cmd_cache = s['func_uses_cmd_cache']  if 'func_uses_cmd_cache' in s else False
                if func_uses_cmd_cache:
                    # The parameter indicates that the command cache need to be passed as
                    # parameter to the transforming function
                    # (For an example: refer function add_interface_attachment())
                    new = func(old, cache)
                else:
                    new  = func(*old) if type(old) == list else func(old)
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
                    if not 'args' in params:
                        raise Exception("fwutils.py:substitute: 'replace' is not supported for the given dictionary in '%s'" % format(params))
                    if not 'key' in s: # need to specify the key in params['args'] that it's value needs to be replaced
                        raise Exception("fwutils.py:substitute: key to replace doesn't specified in substitute '%s'" % format(s))

                    arg_key = s['key']
                    if not params['args'][arg_key]: # make sure specified key is exists in args
                        raise Exception("fwutils.py:substitute: '%s' key doesn't exist in params '%s'" % (arg_key, format(s)))

                    val = params['args'][arg_key]
                    if type(val) == list:  # if value is list, go over the list and check
                        for (idx, p) in list(enumerate(val)):
                            if type(p) == str and old in p:
                                params['args'][arg_key][idx] = params['args'][arg_key][idx].replace(old, str(new))
                    else:
                        raise Exception("fwutils.py:substitute: 'replace' is not supported for the given dictionary in '%s'" % format(params))
                else:  # list
                    for (idx, p) in list(enumerate(params)):
                        if type(p) == str:
                            params.insert(idx, p.replace(old, str(new))) # new variable might be vpp_sw_interface_index which is number, so we stringify it
                            params.remove(p)
            else:
                raise Exception("fwutils.py.substitute: not supported type of substitution in '%s'" % format(params))

        # Once all substitutions are made, remove substitution list from params
        if type(params) is dict:
            del params['substs']
        else:  # list
            params.remove(substs_element)

    def _translate_modify(self, request):
        """Translate modify request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        whitelist = None
        req    = request['message']
        params = request.get('params')
        old_params  = self.cfg_db.get_request_params(request)

        # First of all check if the received parameters differs from the existing ones
        same = fwutils.compare_request_params(params, old_params)
        if same:
            return ([], None)

        api_defs = self.translators.get(req)
        if not api_defs:
            # This 'modify-X' is not supported (yet?)
            return ([], None)

        module = api_defs.get('module')
        assert module, 'there is no module for request "%s"' % req

        api = api_defs.get('api')
        assert api, 'there is no api for request "%s"' % req

        func = getattr(module, api)
        assert func, 'there is no api function for request "%s"' % req

        cmd_list = func(params, old_params)

        if isinstance(cmd_list, list):
            new_cmd_list = []
            for cmd in cmd_list:
                if 'modify' in cmd:
                    whitelist = cmd['whitelist']
                else:
                    new_cmd_list.append(cmd)
            return (new_cmd_list, whitelist)
        else:
            return (cmd_list, None)

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
            if re.match('(modify-|remove-)', req) and not self.cfg_db.exists(__request):
                # Ensure that the aggregated request does not include correspondent 'add-X' before.
                noop = True
                if aggregated_requests:
                    complement_req     = re.sub('(modify-|remove-)','add-', req)
                    complement_request = { 'message': complement_req, 'params': params }
                    if _exist(complement_request, aggregated_requests):
                        noop = False
                if noop:
                    return True
            elif re.match('add-', req) and self.cfg_db.exists(__request):
                # Ensure this is actually not modification request :)
                existing_params = self.cfg_db.get_request_params(__request)
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
                # start-router & stop-router break add-/remove-/modify- convention.
                return True
            elif re.match('modify-interface', req):
                # For modification request ensure that it goes to modify indeed:
                # translate request into commands to execute in order to modify
                # configuration item in Linux/VPP. If this list is empty,
                # the request can be stripped out.
                #
                cmd_list, _ = self._translate_modify(__request)
                if not cmd_list:
                    # Save modify request into database, as it might contain parameters
                    # that don't impact on interface configuration in Linux or in VPP,
                    # like PublicPort, PublicIP, useStun, etc.
                    #
                    # !!!!!!!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!!!!!!!!
                    # We assume the 'modify-interface' request includes full set of
                    # parameters and not only modified ones!
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    #
                    self.cfg_db.update(__request)
                    return True
            return False

        def _exist(__request, requests):
            """Checks if the list of requests has request for the same
            configuration item as the one denoted by the provided __request.
            """
            for r in requests:
                if (__request['message'] == r['message'] and
                    self.cfg_db.is_same_cfg_item(__request, r)):
                    return True
            return False


        if request['message'] != 'aggregated':
            if _should_be_stripped(request):
                self.log.debug("_strip_noop_request: request has no impact: %s" % json.dumps(request))
                return None
        else:  # aggregated request
            out_requests = []
            inp_requests = request['params']['requests']
            for _request in inp_requests:
                if _should_be_stripped(_request, inp_requests):
                    self.log.debug("_strip_noop_request: embedded request has no impact: %s" % json.dumps(request))
                else:
                    out_requests.append(_request)
            if not out_requests:
                self.log.debug("_strip_noop_request: aggregated request has no impact")
                return None
            if len(out_requests) < len(inp_requests):
                self.log.debug("_strip_noop_request: aggregation after strip: %s" % json.dumps(out_requests))
            request['params']['requests'] = out_requests
        return request

    def restore_configuration(self, types=None):
        """Restore configuration.
        Run all configuration translated commands.
        """
        try:
            self.log.info("===restore configuration: started===")

            requests = self.cfg_db.dump(keys=True, types=types)
            if requests:
                for req in requests:
                    reply = fwglobals.g.handle_request(req)
        except Exception as e:
            self.log.excep("restore_configuration failed: %s" % str(e))

        self.log.info("====restore configuration: finished===")

    def sync_full(self, incoming_requests):
        fwglobals.g.agent_api._reset_device_soft()

        sync_request = {
            'message':   'aggregated',
            'params':    { 'requests': incoming_requests },
        }

        reply = self.call(sync_request, dont_revert_on_failure=True)

        if reply['ok'] == 0:
            raise Exception(" _sync_device: router full sync failed: " + str(reply.get('message')))

    def sync(self, incoming_requests, full_sync=False):
        incoming_requests = list([x for x in incoming_requests if x['message'] in self.translators])

        if len(incoming_requests) == 0:
            return True

        sync_list = self.cfg_db.get_sync_list(incoming_requests)

        if len(sync_list) == 0 and not full_sync:
            self.log.info("_sync_device: sync_list is empty, no need to sync")
            return True

        self.log.debug("_sync_device: start smart sync")

        sync_request = {
            'message':   'aggregated',
            'params':    { 'requests': sync_list }
        }

        reply = self.call(sync_request, dont_revert_on_failure=True)

        if reply['ok'] == 1 and not full_sync:
            self.log.debug("_sync_device: smart sync succeeded")
            return True

        # Full sync
        return self.sync_full(incoming_requests)
