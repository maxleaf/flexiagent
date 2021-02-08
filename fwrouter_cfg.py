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
import re
import traceback
import copy

from fwcfg_database import FwCfgDatabase

import fwglobals
import fwrouter_api
import fwutils


class FwRouterCfg(FwCfgDatabase):
    """This is requests DB class representation.

    :param db_file: SQLite DB file name.
    """

    def update(self, request, cmd_list=None, executed=False):
        # The `start-router` does not conform `add-X`, `remove-X`, `modify-X` format
        # handled by the superclass update(), so we handle it here.
        # All the rest are handled by FwCfgDatabase.update().
        #

        req     = request['message']
        try:
            if re.match('start-router', req):
        :param whitelist:   White list of parameters allowed to be modified.
                params  = request.get('params')
                req_key = self._get_request_key(request)
                self.db[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
                self.db[req_key] = entry  # Can't update self.db[req_key] directly, sqldict will ignore such modification
            elif re.match('modify-', req):
                entry = self.db[req_key]
                for key, value in params.items():
                    if isinstance(value, dict):
                        for key2, value2 in value.items():
                            if key2 in whitelist:
                                entry['params'][key][key2] = value2
            else:
                FwCfgDatabase.update(self, request, cmd_list, executed)
        except KeyError:
            pass
        except Exception as e:
            fwglobals.log.error("update(%s) failed: %s, %s" % \
                        (req_key, str(e), str(traceback.format_exc())))
            raise Exception('failed to update request database')

    def dump(self, types=None, escape=None, full=False, keys=False):
        """Dumps router configuration into list of requests
        """
        if not types:
            types = [
                'start-router',
                'add-interface',
                'add-tunnel',
                'add-route',		# routes should come after tunnels, as they might use them
                'add-dhcp-config',
                'add-application',
                'add-multilink-policy'
            ]

        return FwCfgDatabase.dump(self, types, escape, full, keys)

    def dumps(self, types=None, escape=None, full=False):
        """Dumps router configuration into printable string.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        """
        sections = {                # Use stairway to ensure section order in
                                    # output string created by json.dumps()
                                    #
            'start-router':         "======= START COMMAND =======",
            'add-interface':        "======== INTERFACES ========",
            'add-route':            "========= ROUTES =========",
            'add-tunnel':           "========== TUNNELS ==========",
            'add-dhcp-config':      "=========== DHCP CONFIG ===========",
            'add-application':      "============ APPLICATIONS ============",
            'add-multilink-policy': "============= POLICIES ============="
        }

        cfg = self.dump(types=types, escape=escape, full=full, keys=True)
        return FwCfgDatabase.dumps(self, cfg, sections, full)

    def get_interfaces(self, type=None, dev_id=None, ip=None):
        interfaces = self.get_requests('add-interface')
        if not type and not dev_id and not ip:
            return interfaces
        result = []
        for params in interfaces:
            if type and not re.match(type, params['type'], re.IGNORECASE):
                continue
            elif dev_id and dev_id != params['dev_id']:
                continue
            elif ip and not re.match(ip, params['addr']):
                continue
            result.append(params)
        return result

    def get_routes(self):
        return self.get_requests('add-route')

    def get_tunnels(self):
        return self.get_requests('add-tunnel')

    def get_tunnel(self, tunnel_id):
        key = 'add-tunnel:%d' % (tunnel_id)
        return self.get_params(key)

    def get_multilink_policy(self):
        return self.get_params('add-multilink-policy')

    def get_applications(self):
        return self.get_params('add-application')

    def get_wan_interface_gw(self, ip):
        import fwutils
        interfaces = self.get_interfaces(type='wan', ip=ip)
        if not interfaces:
            return (None, None)
        dev_id = interfaces[0]['dev_id']
        gw  = interfaces[0].get('gateway')
        # If gateway not exist in interface configuration, use default
        # This is needed when upgrading from version 1.1.52 to 1.2.X
        if not gw:
            tap = fwutils.dev_id_to_tap(dev_id)
            rip, _ = fwutils.get_interface_gateway(tap)
            return dev_id, rip
        else:
            return dev_id, gw

    def get_sync_list(self, requests):
        """Intersects requests provided within 'requests' argument against
        the requests stored in the local database and generates output list that
        can be used for synchronization of router configuration. This output list
        is called sync-list. It includes sequence of 'remove-X', 'modify-X' and
        'add-X' requests that should be applied to device in order to configure
        it with the configuration, reflected in the input list 'requests'.

        :param requests: list of requests that reflects the desired configuration.
                         The requests are in formant of flexiManage<->flexiEdge
                         message: { 'message': 'add-X', 'params': {...}}.

        :returns: synchronization list - list of 'remove-X', 'modify-X' and
                         'add-X' requests that takes device to the desired
                         configuration if applied to the device.
        """

        # Firstly we hack a little bit the input list as follows:
        # build dictionary out of this list where values are list elements
        # (requests) and keys are request keys that local database would use
        # to store these requests. Accidentally these are exactly same keys
        # dumped by fwglobals.g.router_cfg.dump() used below ;)
        #
        input_requests = {}
        for request in copy.deepcopy(requests): # Use deepcopy as we might modify input_requests[key] below
            key = self._get_request_key(request)
            input_requests.update({key:request})

        # Now dump local configuration in order of 'remove-X' list.
        # We will go over dumped requests and filter out requests that present
        # in the input list and that have same parameters. They correspond to
        # configuration items that should be not touched by synchronization.
        # The dumped requests that present in the input list but have different
        # parameters stand for modifications.
        #
        dumped_requests = fwglobals.g.router_cfg.dump(keys=True)
        output_requests = []

        for dumped_request in dumped_requests:
            dumped_key = dumped_request['key']
            if dumped_key in input_requests:
                # The configuration item presents in the input list.
                #
                dumped_params = dumped_request.get('params')
                input_params  = input_requests[dumped_key].get('params')
                if fwutils.compare_request_params(dumped_params, input_params):
                    # The configuration item has exactly same parameters.
                    # It does not require sync, so remove it from input list.
                    #
                    del input_requests[dumped_key]
                else:
                    # The configuration item should be modified.
                    # Rename requests in input list with 'modify-X'.
                    #
                    # At this stage only 'modify-interface' is supported,
                    # so for the rest types of configuration items we add
                    # the correspondent 'remove-X' request with current
                    # parameters to the output list and later in this function
                    # we will add the 'add-X' request from the input list.
                    #
                    if dumped_request['message'] == 'add-interface':
                        input_requests[dumped_key]['message'] = 'modify-interface'
                    else:
                        dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                        output_requests.append(dumped_request)
            else:
                # The configuration item does not present in the input list.
                # So it stands for item to be removed. Add correspondent request
                # to the output list.
                # Ignore 'start-router', 'stop-router', etc as they are not
                # an configuration items.
                #
                if not re.search('(start|stop)-router', dumped_request['message']):
                    dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                    output_requests.append(dumped_request)


        # At this point the input list includes 'add-X' requests that stand
        # for new or for modified configuration items.
        # Just go and add them to the output list 'as-is'.
        #
        output_requests += list(input_requests.values())

        return output_requests

