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

import json
import pickle
import re
import sqlite3
import traceback
import copy

from sqlitedict import SqliteDict

import fwglobals
import fwutils

from fwlog import FwSyslog
from fwobject import FwObject

def decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return pickle.loads(bytes(obj), encoding="latin1")

def encode(obj):
    """Deserialize objects retrieved from SQLite."""
    return sqlite3.Binary(pickle.dumps(obj, protocol=2))

class FwCfgDatabase(FwObject):
    """This is requests DB class representation.
    Persistent database that is used to keep configuration requests received from flexiManage.
    The requests are stored along with their translations into command list.
    We used this class as a wrapper to Sqlite for our specific format:

    [
        {
            "Executed": { Indicates if command are already executed },
            "Key": { The unique key for each request from flexiManage. e.g. "add-interface:pci:0000:08:01" },
            "Params": { Dictonery with params received from flexiManage },
            "Commands": [ list of translated commands ]
        }
    ]

    :param db_file: SQLite DB file name.
    """
    def __init__(self, db_file):
        """Constructor method
        """
        FwObject.__init__(self)

        self.db_filename = db_file
        self.db = SqliteDict(db_file, autocommit=True, encode=encode, decode=decode)

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

    def close(self):
        self.db.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for req_key in self.db:
            del self.db[req_key]

        # Reset configuration to the value, that differs from one calculated
        # by the flexiManage. This is to enforce flexiManage to issue 'sync-device'
        # in order to fill the configuration database again with most updated
        # configuration.
        fwutils.reset_device_config_signature("empty_cfg", log=False)

    def set_translators(self, translators):
       self.translators = translators

    def set_logger(self, logger):
       self.log = logger if logger else fwglobals.log

    def is_same_cfg_item(self, request1, request2):
        """Checks if provided requests stand for the same configuration item.
        """
        req_key1 = self._get_request_key(request1)
        req_key2 = self._get_request_key(request2)
        if req_key1 == req_key2:
            return True
        return False

    def _get_request_key(self, request):
        req     = request['message']
        params  = request.get('params')

        # add-/remove-/modify-X requests use key function defined for 'add-X'.
        # start-router & stop-router break add-/remove-/modify- convention.
        if req=='start-router' or req=='stop-router':
            src_req = 'start-router'
        else:
            src_req = re.sub(r'^\w+', 'add', req)

        key_func = getattr(self.translators[src_req]['module'], 'get_request_key')
        return key_func(params)

    def update(self, request, cmd_list=None, executed=False, whitelist=None):
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
        :param whitelist:   White list of parameters allowed to be modified.
        :returns: None.
        """
        req     = request['message']
        params  = request.get('params')
        req_key = self._get_request_key(request)

        try:
            if re.match('add-', req):
                self.db[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
            elif re.match('modify-interface', req):
                entry = self.db[req_key]
                entry.update({'params' : params})
                self.db[req_key] = entry
            elif re.match('modify-', req):
                if whitelist:
                    entry = self.db[req_key]
                    for key, value in params.items():
                        if isinstance(value, dict):
                            for key2, value2 in value.items():
                                if key2 in whitelist:
                                    entry['params'][key][key2] = value2
                    self.db[req_key] = entry  # Can't update self.db[req_key] directly, sqldict will ignore such modification
            else:
                del self.db[req_key]

        except KeyError:
            pass
        except Exception as e:
            self.log.error("update(%s) failed: %s, %s" % \
                        (req_key, str(e), str(traceback.format_exc())))
            raise Exception('failed to update request database')

    def get_request_params(self, request):
        req_key = self._get_request_key(request)
        return self.get_params(req_key)

    def get_request_cmd_list(self, request):
        req_key = self._get_request_key(request)
        return self.get_cmd_list(req_key)

    def get_cmd_list(self, req_key):
        """Retrives translation of the request to list of commands.

        :param request: The request as it would be received on network,
                        including name (request['message']) and parmateres
                        (request['params']) if exist.

        :returns: the tuple of the command list and the 'executed' flag
        """
        if not req_key in self.db:
            return (None, None)
        return (self.db[req_key].get('cmd_list'), self.db[req_key].get('executed'))

    def exists(self, request):
        """Check if entry exists in DB.

        :param request: the configuration request as it would be received from flexiManage

        :returns: 'True' if request exists and 'False' otherwise.
        """
        req_key = self._get_request_key(request)
        res = True if req_key in self.db else False
        return res

    def get_params(self, req_key):
        """Retrives parameters of the provided configuration request.
        This function can be used to find parameters of configuration item
        before modification.

        :param request: The configuration request, e.g. modify-interface.
        :returns: parameters of the request stored in the database.
        """
        if req_key in self.db:
            return self.db[req_key].get('params')
        return None

    def dump(self, types, escape=None, full=False, keys=False):
        """Dumps database configuration into list of requests that look exactly
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
            raise Exception('"types" was not provided - no items to fetch from db')

        if escape:
            for t in escape:
                types.remove(t)

        # The dump is O(num_types x n) - improve that on demand!
        cfg     = []
        db_keys = sorted(self.db.keys())  # The key order might be affected by dictionary content, so sort it
        for req in types:
            for key in db_keys:
                if re.match(req, key):
                    request = {
                        'message': self.db[key].get('request',""),
                        'params':  self.db[key].get('params', "")
                    }
                    if request['params'] == None:  # flexiManage team doesn't like None :)
                        request['params'] = {}
                    if full:
                        request.update({
                            'cmd_list': self.db[key].get('cmd_list', ""),
                            'executed': self.db[key].get('executed', "")})
                    if keys:
                        request.update({'key': key})
                    cfg.append(request)
        return cfg

    def dumps(self, cfg, sections, full):
        """Dumps configuration into printable string.

        :param cfg:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param sections: list of sections to group request with same types. e.g. interfaces, tunnels
        """
        out = {}
        prev_msg = { 'message': 'undefined' }

        for msg in cfg:
            # Add new section
            if msg['message'] != prev_msg['message']:
                prev_msg['message'] = msg['message']
                section_name = sections[msg['message']]
                out[section_name] = []

            # Add configuration item to section
            item = {
                'Key':    msg['key'],
                'Params': msg['params']
            }
            if full:
                item.update({'Executed': str(msg['executed'])})
                item.update({'Commands': fwutils.yaml_dump(msg['cmd_list']).split('\n')})
            out[section_name].append(item)
        if not out:
            return ''
        return json.dumps(out, indent=2, sort_keys=True)

    def get_requests(self, req):
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
        dumped_requests = self.dump(keys=True)
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
        output_requests += list(input_requests.values())

        return output_requests