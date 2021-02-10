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
import fnmatch
import fwglobals
import fwutils
import time

try:
    from vpp_papi import VPPApiClient
    vppWrapper = False
except:
    print("vpp_papi library not found, using VPP dummy wrapper. Only for testing!!!")
    from vpp_papi_dummy import VPPApiClient
    vppWrapper = True

class VPP_API:
    """This is VPP API class representation.
    """
    def __init__(self):
        """Constructor method
        """
        self.connected_to_vpp = False
        if fwutils.vpp_does_run():
            self.connect_to_vpp()

    def finalize(self):
        """Destructor method
        """
        if self.connected_to_vpp:
            self.disconnect_from_vpp()

    def connect_to_vpp(self, vpp_json_dir='/usr/share/vpp/api/'):
        """Connect to VPP.

        :param vpp_json_dir:         Path to json files with API description.
        """
        if self.connected_to_vpp:
            return True
        fwglobals.log.debug("connect_to_vpp: loading VPP API files")
        self.jsonfiles = []
        for root, _, filenames in os.walk(vpp_json_dir):
            for filename in fnmatch.filter(filenames, '*.api.json'):
                self.jsonfiles.append(os.path.join(root, filename))
        if not self.jsonfiles and not vppWrapper:
            raise Exception("connect_to_vpp: no vpp api files were found")
        fwglobals.log.debug("connect_to_vpp: connecting")

        self.vpp = VPPApiClient(apifiles=self.jsonfiles, use_socket=True)
        num_retries = 5
        for i in range(num_retries):
            try:
                fwglobals.log.debug("connect_to_vpp: trying to connect, num " + str(i))
                self.vpp.connect('fwagent')
                break
            except Exception as e:
                if not fwutils.vpp_does_run():  # No need to retry if vpp crashed
                    raise Exception("vpp process not found")
                if i == num_retries-1:
                    raise e
                else:
                    time.sleep(20)
        self.connected_to_vpp = True
        fwglobals.log.debug("connect_to_vpp: connected")

#        vpp_methods = []
#        for method_name in dir(self.vpp):
#            if callable(getattr(self.vpp, method_name)):
#                vpp_methods.append(method_name)
#        print("vpp.methods: " + format(vpp_methods))
#        vpp_api_methods = []
#        for method_name in dir(self.vpp.api):
#            if callable(getattr(self.vpp.api, method_name)):
#                vpp_api_methods.append(method_name)
#        print("vpp.api.methods: " + format(vpp_api_methods))

    def disconnect_from_vpp(self):
        """Disconnect from VPP.

        :returns: None.
        """
        if self.connected_to_vpp:
            self.vpp.disconnect()
            self.connected_to_vpp = False
            fwglobals.log.debug("disconnect_from_vpp: disconnected")
        else:
            fwglobals.log.debug("disconnect_from_vpp: not connected")

    # result - describes what field of the object returned by the API,
    #          should be stored in cache, what cache and what key
    #          should be used for that:
    #           {
    #               'result_attr' : <name of attribute of returned object> ,
    #               'cache'       : <cache to store the value of the attribute in> ,
    #               'key'         : <key by which to store the value>
    #           }
    #
    def call_simple(self, request, result=None):
        """Call VPP command.

        :param api:            API name.
        :param params:         Parameters.
        :param result:         Cache to store results.

        :returns: Reply message.
        """
        api    = request['message']
        params = request.get('params')

        if not self.connected_to_vpp:
            reply = {'message':"vpp doesn't run", 'ok':0}
            return reply

        api_func = getattr(self.vpp.api, api)
        assert api_func, 'vpp_api: api=%s not found' % (api)

        rv = api_func(**params) if params else api_func()
        if rv and rv.retval == 0:
            if result:      # If asked to store some attribute of the returned object in cache
                res = getattr(rv, result['result_attr'])
                result['cache'][result['key']] = res
            reply = {'ok':1}
        else:
            fwglobals.log.error('rv=%s: %s(%s)' % (rv.retval, api, format(params)))
            reply = {'message':api + ' failed', 'ok':0}
        return reply

    def cli(self, cmd):
        """Execute command in VPP CLI.

        :param cmd:            VPP CLI command.

        :returns: Reply message.
        """
        if not self.connected_to_vpp:
            fwglobals.log.excep("cli: not connected to VPP")
            return None
        res = self.vpp.api.cli_inband(cmd=cmd)
        if res is None:
            return None
        return res.reply
