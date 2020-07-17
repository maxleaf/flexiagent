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

import os
import Pyro4
import re
import time
import traceback

import fwagent
import fwglobals
import fwutils

supported_apis = {
    'inject_requests': "inject_requests(<filename.json>, [ignore_errors])\n" + \
                       "       <filename.json> - file with list of requests in JSON format\n" +
                       "       ignore_errors   - If presents, failed requests will not break execution"
}
api_args_parsers = {
    'inject_requests': lambda args: parse_args_inject_requests(args)
}

class FwagentCliErrorParser(Exception):
    def __init__(self, message=None):
        self.message = message if message else 'FwagentCliErrorParser'
    def __str__(self):
        return self.message

class FwagentCli:
    """This class implements abstraction of fwagent shell.
    On construction it connects to agent that runs on background,
    and than runs infinite read-and-execute loop:
        - reads Fwagent API function name and it's arguments,
          e.g. 'inject_requests(requests.json, ingore_errors)'
        - parses the user input string into function name and list of parameters
        - invokes the remote function on agent instance
        The agent API to be invoked can be provided in one line with command,
    To stop the read-n-execute loop just ^C it, or enter 'quit' or 'exit' command.

        If no agent runs on background, the FwagentCli will create new instance
    of Fwagent and will use it. This instance is  destroyed on FwagentCli exit.
    """
    def __init__(self, agent_linger=None):
        """Constructor.
        :param agent_linger: sleep duration before destroying local instance
                             of fwagent. It might be used to keep vpp running
                             for a linger number of seconds, as agent
                             termination kills the vpp.
        """
        self.daemon       = None
        self.agent        = None
        self.agent_linger = agent_linger
        self.prompt       = 'fwagent> '

        try:
            self.daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
            self.daemon.ping()   # Check if daemon runs. If it does not, create local instance of Fwagent
        except Pyro4.errors.CommunicationError:
            fwglobals.log.warning("FwagentCli: no daemon Fwagent was found, use local instance")
            self.daemon = None

    def __enter__(self):
        if not self.daemon:
	        fwglobals.g.initialize_agent()
	        self.agent = fwglobals.g.fwagent
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        if self.agent:
            # If we used local instance of Fwagent and not daemon, kill it.
            # Otherwise we might hang up in vpp watchdog,
            # if router was started by cli execution.
            if self.agent_linger:
                time.sleep(self.agent_linger)
            fwglobals.g.finalize_agent()

    def run_loop(self):
        while True:
            try:
                api_str = raw_input(self.prompt)
                if api_str == '':
                    continue
                elif api_str == 'q' or api_str == 'quit' or api_str == 'exit':
                    break
                elif api_str == 'h' or api_str == 'help':
                    print(self.prompt + "enter 'quit' or one of API-s listed below:")
                    for api_name in sorted(supported_apis.keys()):
                        print('----------------------------------------------------')
                        print(supported_apis[api_name])
                elif api_str == '\x1b[A' or api_str == '\x1b[B':
                    print('ARROWS ARE NOT SUPPORTED YET ;)')
                else:
                    self.execute(api_str)
            except Exception as e:
                print(self.prompt + str(e))

    def execute(self, api_str):
        try:
            (api_name, api_args) = parse_api_str(api_str)
            if self.daemon:
                rpc_api_func = getattr(self.daemon, 'api')
                rpc_api_func(api_name, api_args)
            elif self.agent:
                api_func = getattr(self.agent, api_name)
                api_func(**api_args)
            fwglobals.log.info(self.prompt + 'SUCCESS')
        except FwagentCliErrorParser as e:
            fwglobals.log.error(self.prompt + 'FAILED to parse api call: %s' % str(e))
            fwglobals.log.error(self.prompt + 'type "help" to see available commands')
        except Exception as e:
            fwglobals.log.error(self.prompt + 'FAILED: ' + str(e))

def parse_api_str(api_str):
    """Parse 'inject_requests(<requests.json>, ingore_errors)' string into
    function name and it's parameters in form of dictionary.
    """
    match = re.match(r'^[ ]*([^ ()]+)\((.*)\)[ ]*$', api_str)
    if not match:
        raise FwagentCliErrorParser('BAD API SYNTAX')
    api_name = match.group(1)
    if not api_name in supported_apis:
        raise FwagentCliErrorParser('NOT SUPPORTED API: ' + api_name)
    arg_list = match.group(2).split(',')
    arg_list = [arg.strip() for arg in arg_list]
    api_args = api_args_parsers[api_name](arg_list)
    return (api_name, api_args)

def parse_args_inject_requests(arg_list):
    # inject_requests(<filename>, [ignore_errors])
    args = {}

    if 'ignore_errors' in arg_list:
        args['ignore_errors'] = True
        arg_list.remove('ignore_errors')

    if len(arg_list) == 0:
        raise FwagentCliErrorParser("no filename was provided")
    filename = arg_list[0]
    if (os.path.exists(filename) and os.path.isfile(filename)):
        args['filename'] = filename
    else:
        raise FwagentCliErrorParser("file '%s' not exists" % filename)
    return args
