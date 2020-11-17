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
    def __init__(self):
        """Constructor.
        """
        self.daemon       = None
        self.agent        = None
        self.prompt       = 'fwagent> '

        try:
            self.daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
            self.daemon.ping()   # Check if daemon runs. If it does not, create local instance of Fwagent
        except Pyro4.errors.CommunicationError:
            fwglobals.log.warning("FwagentCli: no daemon Fwagent was found, use local instance")
            self.daemon = None

    def __enter__(self):
        if not self.daemon:
	        self.agent = fwglobals.g.initialize_agent(standalone=True)
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
            self.agent = fwglobals.g.finalize_agent()

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
                    ret = self.execute(api_str)
                    if ret['succeeded']:
                        fwglobals.log.info(self.prompt + 'SUCCESS')
                    else:
                        fwglobals.log.info(self.prompt + 'FAILURE')
                        fwglobals.log.error(self.prompt + ret['error'])
            except Exception as e:
                print(self.prompt + 'FAILURE: ' + str(e))

    def execute(self, api_args):
        """Executes API provided by user with
        'fwagent cli --api <api name> [<api arg1>, ...]` command.

         :param api_args: the user input as a list, where the list[0] element
                          is API name and rest elements are API arguments.
        """
        try:
            # Convert list of "<name>=<val>" elements into dictionary
            api_name = api_args[0]
            api_args = { arg.split("=")[0] : arg.split("=")[1] for arg in api_args[1:] }

            if self.daemon:
                rpc_api_func = getattr(self.daemon, 'api')
                ret = rpc_api_func(api_name, api_args)
            elif self.agent:
                api_func = getattr(self.agent, api_name)
                ret = api_func(**api_args)
            return { 'succeeded': True, 'return-value': ret }

        except Exception as e:
            return { 'succeeded': False, 'error': str(e) }

