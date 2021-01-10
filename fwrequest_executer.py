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

import fwglobals
import fwutils
import traceback

class FwRequestExecuter:
    """This is Request Executer class representation.
    The Request-Executer class provides a solution to translate flexiManage requests into a set of commands.
    Save them on a file and execute them carefully with a revert functionality in case of failure.

    :param modules: list of modules to use to translate the requests
    :param translators: list of supported requests to translate
    :param db_class: an instance of db wrapper class
    :param revert_callback: callback to run in case of revert failure (Optional)
    """
    
    def __init__(self, modules, translators, db_class, revert_callback = None):
        """Constructor method.
        """
        self.modules = modules
        self.translators = translators
        self.db_class = db_class
        self.revert_callback = revert_callback

    def __enter__(self):
        return self

    def translate(self, request):
        """Translate request in a series of commands.

        :param request: The request received from flexiManage.

        :returns: list of commands.
        """
        req    = request['message']
        params = request.get('params')

        api_defs = self.translators.get(req)
        assert api_defs, 'FwRequestExecuter: there is no api for request "%s"' % req

        module = self.modules.get(self.translators[req]['module'])
        assert module, 'FwRequestExecuter: there is no module for request "%s"' % req

        func = getattr(module, self.translators[req]['api'])
        assert func, 'FwRequestExecuter: there is no api function for request "%s"' % req

        if self.translators[req]['api'] == 'revert':
            cmd_list = func(request, self.db_class)
            return cmd_list

        cmd_list = func(params) if params else func()
        return cmd_list

    def execute(self, request, cmd_list, filter=None):
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

        fwglobals.log.debug("=== start execution of %s ===" % (req))

        for idx, t in enumerate(cmd_list):      # 't' stands for command Tuple, though it is Python Dictionary :)
            cmd = t['cmd']

            # If filter was provided, execute only commands that have the provided filter
            if filter:
                if not 'filter' in cmd or cmd['filter'] != filter:
                    fwglobals.log.debug("_execute: filter out command by filter=%s (req=%s, cmd=%s, cmd['filter']=%s, params=%s)" %
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
                fwglobals.log.debug("_execute: %s(%s)" % (cmd['name'], params))

                # Now execute command
                result = None if not 'cache_ret_val' in cmd else \
                    { 'result_attr' : cmd['cache_ret_val'][0] , 'cache' : cmd_cache , 'key' :  cmd['cache_ret_val'][1] }
                reply = fwglobals.g.handle_request({ 'message': cmd['name'], 'params':  cmd.get('params')}, result)
                if reply['ok'] == 0:        # On failure go back revert already executed commands
                    fwglobals.log.debug("%s failed ('ok' is 0)" % cmd['name'])
                    raise Exception("API failed: %s" % reply['message'])

            except Exception as e:
                err_str = "_execute: %s(%s) failed: %s, %s" % (cmd['name'], format(cmd.get('params')), str(e), str(traceback.format_exc()))
                fwglobals.log.error(err_str)
                fwglobals.log.debug("=== failed execution of %s ===" % (req))
                if fwglobals.g.router_api.state_is_starting_stopping():
                    fwutils.dump()
                # On failure go back to the begining of list and revert executed commands.
                self.revert(cmd_list, idx)
                fwglobals.log.debug("=== finished revert of %s ===" % (req))
                raise Exception('failed to ' + cmd['descr'])

            # At this point the execution succeeded.
            # Now substitute the revert command, as it will be needed for complement request, e.g. for remove-tunnel.
            if 'revert' in t and 'params' in t['revert']:
                try:
                    self.substitute(cmd_cache, t['revert'].get('params'))
                except Exception as e:
                    fwglobals.log.excep("_execute: failed to substitute revert command: %s\n%s, %s" % \
                                (str(t), str(e), str(traceback.format_exc())))
                    fwglobals.log.debug("=== failed execution of %s ===" % (req))
                    self.revert(cmd_list, idx)
                    raise e

        fwglobals.log.debug("=== end execution of %s ===" % (req))

    def revert(self, cmd_list, idx_failed_cmd=-1):
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

                    if self.revert_callback:
                        self.revert_callback(t)

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
