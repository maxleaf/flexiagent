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
import fwsystem_api
import fwutils


class FwSystemCfg(FwCfgDatabase):
    """This is requests DB class representation.
    
    :param db_file: SQLite DB file name.
    """
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
        self.db.clean()

    def _get_request_key(self, request):
        """Generates uniq key for request out of request name and
        request parameters. To do that uses the get_request_key() function
        that MUST be defined in the correspondent translator file,
        """
        req     = request['message']
        params  = request.get('params')

        # add-/remove-/modify-X requests use key function defined for 'add-X'.
        src_req = re.sub(r'^\w+', 'add', req)
        
        key_module  = fwsystem_api.fwsystem_modules.get(fwsystem_api.fwsystem_translators[src_req]['module'])
        key_func    = getattr(key_module, 'get_request_key')
        return key_func(params)

    def update(self, request, cmd_list=None, executed=False):
        """Save configuration request into DB.
        The 'add-X' configuration requests are stored in DB, the 'remove-X'
        requests are not stored but remove the correspondent 'add-X' requests.

        :param request:     The request received from flexiManage.
        :param cmd_list:    List of commands to be executed in order to fullfil
                            configuration request. The command can invoke VPP API,
                            run Linux shell commands, update internal agent objects,
                            etc. They are generated by generated by translation.
        :param executed:    The 'executed' flag - True if the configuration
                            request was translated and executed, False if it was
                            translated but was not executed.
        :returns: None.
        """
        req     = request['message']
        params  = request.get('params')
        req_key = self._get_request_key(request)

        try:
            if re.match('add-', req):
                self.db[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
            elif re.match('modify-', req):
                entry = self.db[req_key]
                entry.update({'params' : params})
                self.db[req_key] = entry 
            else:
                del self.db[req_key]

        except KeyError:
            pass
        except Exception as e:
            fwglobals.log.error("update(%s) failed: %s, %s" % \
                        (req_key, str(e), str(traceback.format_exc())))
            raise Exception('failed to update request database')
    
    def get_request_cmd_list(self, request):
        req_key = self._get_request_key(request)
        return self.get_cmd_list(req_key)
        
    def dump(self, types=None, escape=None, full=False, keys=False):
        """Dumps system configuration into list of requests.
        """
        
        if not types:
            types = [
                'add-lte',
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
            'add-lte':         "======= LTE =======",
        }

        cfg = self.dump(types=types, escape=escape, full=full, keys=True)

        return fwutils.dumps_config(cfg, sections)

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
        dumped_requests = fwglobals.g.system_cfg.dump(keys=True)
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
                    dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                    output_requests.append(dumped_request)
            else:
                # The configuration item does not present in the input list.
                # So it stands for item to be removed. Add correspondent request
                # to the output list.
                # Ignore 'start-router', 'stop-router', etc as they are not
                # an configuration items.
                #
                dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                output_requests.append(dumped_request)


        # At this point the input list includes 'add-X' requests that stand
        # for new or for modified configuration items.
        # Just go and add them to the output list 'as-is'.
        #
        output_requests += input_requests.values()

        return output_requests

    def sync(self, incoming_requests, full_sync=False):
        incoming_requests = list(filter(lambda x: x['message'] in fwsystem_api.fwsystem_translators, incoming_requests))        

        # get sync lists
        sync_list = self.get_sync_list(incoming_requests)

        if len(sync_list) == 0:
            fwglobals.log.info("_sync_device: system sync_list is empty, no need to sync")
            return True

        if full_sync:
            fwglobals.log.debug("_sync_device: start full sync")

        all_succeeded = True
        for req in sync_list:
            reply = fwglobals.g.system_api.call(req)
            if reply['ok'] == 0:
                all_succeeded = False
                break

        if reply['ok'] == 0 and full_sync:
            raise Exception(" _sync_device: system full sync failed: " + str(reply.get('message')))

        return all_succeeded
