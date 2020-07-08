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

import json
import os
import re
import traceback
import yaml

from sqlitedict import SqliteDict

import fwglobals
import fwrouter_api
import fwutils


class FwRouterCfg:
    """This is requests DB class representation.

    :param db_file: SQLite DB file name.
    """
    def __init__(self, db_file):
        """Constructor method
        """
        self.db_filename = db_file
        self.db = SqliteDict(db_file, autocommit=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        self.db.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for req_key in self.db:
            del self.db[req_key]

    def _get_request_key(self, req, params):
        """Generates uniq key for request out of request name 'req' and
        request parameters 'params'. To do that uses function defined in the
        correspondent translator file, e.g. fwtranslate_add_tunnel.py.
        """
        src_req      = fwrouter_api.fwrouter_translators[req].get('src', req)  # 'remove-X' requests use key generator of correspondent 'add-X' requests
        src_module   = fwrouter_api.fwrouter_modules.get(fwrouter_api.fwrouter_translators[src_req]['module'])
        src_key_func = getattr(src_module, fwrouter_api.fwrouter_translators[src_req]['key_func'])
        src_req_key  = src_key_func(params)
        return src_req_key

    def update(self, req, params, cmd_list, executed):
        """Save configuration request into DB.
        The 'add-X' configuration requests are stored in DB, the 'remove-X'
        requests are not stored but remove the correspondent 'add-X' requests.

        :param req:         The request, e.g. 'add-tunnel'.
        :param params:      The dictionary with request parameters, e.g. {'id':1}.
        :param cmd_list:    List of commands to be executed in order to fullfil
                            configuration request. The command can invoke VPP API,
                            run Linux shell commands, update internal agent objects,
                            etc. They are generated by generated by translation.
        :param executed:    The 'executed' flag - True if the configuration
                            request was translated and executed, False if it was
                            translated but was not executed.
        :returns: None.
        """
        req_key = self._get_request_key(req, params)
        try:
            if re.match('add-', req) or re.match('start-router', req):
                self.db[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
            else:
                del self.db[req_key]
        except KeyError:
            pass
        except Exception as e:
            fwglobals.log.error("FwRouterCfg.update(%s) failed: %s, %s" % \
                        (req_key, str(e), traceback.format_exc()))
            raise Exception('failed to update request database')


    def get_request_params(self, req, params):
        """Retrives parameters of the request with name 'req' and parameters
        'params'. I know that it sounds weired :) This is hack. We use this
        function to retrieve parameters of the 'add-X' requests stored in DB,
        when the provided request is correspondent 'remove-X'.
        Note:
            - the 'remove-X' requests are not stored in DB
            - the 'remove-X' 'params' is a subset of the 'add-X' 'params',
              which is sufficient to generate DB key.

        :param req:         The name of the 'remove-X' request, e.g. 'remove-tunnel'.
        :param params:      The parameters of the 'remove-X' request.

        :returns: the parameters of the correspondent 'add-X' request.
        """
        req_key = self._get_request_key(req, params)
        if not req_key in self.db:
            return None
        return self.db[req_key].get('params')

    def get_request_cmd_list(self, req, params):
        """Retrives translation of the request to list of commands.

        :param req:    The name of the request, e.g. 'remove-tunnel'
        :param params: The parameters of the request, e.g. {'id':'1'}

        :returns: the tuple of the command list and the 'executed' flag
        """
        req_key = self._get_request_key(req, params)
        if not req_key in self.db:
            return (None, None)
        return (self.db[req_key].get('cmd_list'), self.db[req_key].get('executed'))

    def exists(self, req, params=None):
        """Check if entry exists in DB.

        :param req:  name of configuration request.

        :returns: 'True' if request exists and 'False' otherwise.
        """
        req_key = self._get_request_key(req, params)
        res = True if req_key in self.db else False
        return res

    def dump(self, types=None, escape=None, full=False, keys=False):
        """Dumps router configuration into list of requests that look exactly
        as they would look if were received from server.

        Note the dump order of configuration requests follows oreder of request
        types in 'types' argument.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        :param keys:   return requests with request key used by DB to identify request.

        :returns: list of configuration requests stored in DB.
        """
        if not types:
            types = [
                'start-router',
                'add-interface',
                'add-route',
                'add-tunnel',
                'add-dhcp-config',
                'add-application',
                'add-multilink-policy'
            ]
        if escape:
            for t in escape:
                types.remove(t)

        # The dump is O(num_types x n) - improve that on demand!
        cfg = []
        for req in types:
            for key in self.db:
                if re.match(req, key):
                    request = {
                        'message': self.db[key].get('request',""),
                        'params':  self.db[key].get('params', "")
                    }
                    if full:
                        request.update({
                            'cmd_list': self.db[key].get('cmd_list', ""),
                            'executed': self.db[key].get('executed', "")})
                    if keys:
                        request.update({'key': key})
                    cfg.append(request)
        return cfg

    def dumps(self, types=None, escape=None, full=False):
        """Dumps router configuration into printable string.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        """
        separators = {
            'start-router':         "======== START COMMAND =======",
            'add-interface':        "========== INTERFACES ========",
            'add-route':            "============ ROUTES ==========",
            'add-tunnel':           "============ TUNNELS =========",
            'add-dhcp-config':      "========= DHCP CONFIG ========",
            'add-application':      "========= APPLICATIONS =======",
            'add-multilink-policy': "=========== POLICIES ========="
        }

        out      = ''
        prev_msg = { 'message': 'undefined' }

        cfg = self.dump(types=types, escape=escape, full=full, keys=True)
        for msg in cfg:
            # Print separator between sections
            if msg['message'] != prev_msg['message']:
                out += separators[msg['message']] + "\n"
                prev_msg['message'] = msg['message']

            # Print configuration item in section
            out += "Key: %s\n" % msg['key']
            out += "%s\n" % json.dumps(msg['params'], sort_keys=True, indent=2)
            if full:
                out += "Executed: %s\n" % str(msg['executed'])
                out += "Commands:\n  %s" % fwutils.yaml_dump(msg['cmd_list'])
        return out

    def _get_requests(self, req):
        """Retrives list of configuration requests parameters for requests with
        the 'req' name.
        This is generic function wrapped by request specific one-line APIs,
        like get_tunnels().

        :param req:         The request name, e.g. 'add-tunnel'.
        :returns: list of request parameters.
        """
        requests = []
        for key in self.db:
            if re.match(req, key):
                requests.append(self.db[key]['params'])
        return requests

    def get_interfaces(self, type=None):
        interfaces = self._get_requests('add-interface')
        if not type:
            return interfaces
        for params in interfaces:
            if not re.match('wan', params['type'], re.IGNORECASE):
                interfaces.remove(params)   # Use wasteful remove() as number of interfaces is O(1)
        return interfaces

    def get_tunnels(self):
        return self._get_requests('add-tunnel')

    def get_multilink_policy(self):
        if 'add-multilink-policy' in self.db:
            return self.db['add-multilink-policy']['params']
        return None

    def get_lan_interface_names(self):
        import fwutils
        if_names = []
        interfaces = self.get_interfaces()
        for params in interfaces:
            if re.match('lan', params['type'], re.IGNORECASE):
                sw_if_index = fwutils.pci_to_vpp_sw_if_index(params['pci'])
                if_name = fwutils.vpp_sw_if_index_to_name(sw_if_index)
                if_names.append(if_name)
        return if_names

    def get_tunnel_interface_names(self):
        import fwutils
        if_names = []
        tunnels = self.get_tunnels()
        for params in tunnels:
            sw_if_index = fwutils.vpp_ip_to_sw_if_index(params['loopback-iface']['addr'])
            if_name = fwutils.vpp_sw_if_index_to_name(sw_if_index)
            if_names.append(if_name)
        return if_names

    def get_wan_interface_gw(self, ip):
        import fwutils
        interfaces = self.get_interfaces()
        for params in interfaces:
            if re.match('wan', params['type'], re.IGNORECASE):
                if re.search(ip, params['addr']):
                    pci = params['pci']
                    gw  = params.get('gateway')
                    # If gateway not exist in interface configuration, use default
                    # This is needed when upgrading from version 1.1.52 to 1.2.X
                    if not gw:
                        tap = fwutils.pci_to_tap(pci)
                        rip, unused_metric = fwutils.get_linux_interface_gateway(tap)
                        return pci, rip
                    else:
                        return pci, gw
        return (None, None)


################################################################################
#    GLOBAL UTILITY FUNCTION
################################################################################

def dump(full=False):
    """Dumps router configuration into list of requests that look exactly
    as they would look if were received from server.

    :param full: return requests together with translated commands.

    :returns: list of configuration requests stored in DB.
    """
    cfg = []
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        cfg = router_cfg.dump(full)
    return cfg

def print_basic(full=False):
    """Prints basic router configuration onto screen: interfaces, routes,
    tunnels, DHCP, etc. Does not print application identifications and multilink
    policies.

    :param full: prints requests together with translated commands.
    """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        print(router_cfg.dumps(full=full, escape=['add-application','add-multilink-policy']))

def print_multilink(full=False):
    """Prints router multilink configuration onto screen.

    :param full: prints requests together with translated commands.
    """
    with FwRouterCfg(fwglobals.g.ROUTER_CFG_FILE) as router_cfg:
        print(router_cfg.dumps(full=full, types=['add-application','add-multilink-policy']))
