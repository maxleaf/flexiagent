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

import hashlib
import json
import re
import traceback

from sqlitedict import SqliteDict

import fwglobals


class FwDatabaseCfg:
    """This is requests DB class representation.

    :param db_file: SQLite DB file name.
    """
    def __init__(self, db_file):
        """Constructor method
        """
        self.db_filename = db_file
        self.db = SqliteDict(db_file, autocommit=True)

        if self.db.get('signature') is None:
            self.db['signature'] = ""

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

    def get_entry(self,key):
        return self.db.get(key)

    def set_entry(self, key, value):
        self.db[key] = value

    def delete_entry(self, key):
        del self.db[key]

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
        #
        self.reset_signature("empty_cfg", log=False)

    def get_request_params(self, req_key):
        """Retrives parameters of the request as they are stored in DB.
        I know that it sounds weired, as request includes parameters in 'params'
        field :) This is hack. We use this function to retrieve parameters
        of the 'add-X' requests stored in DB, when the provided request is
        correspondent 'remove-X'.
        Note:
            - the 'remove-X' requests are not stored in DB
            - the 'remove-X' 'params' is a subset of the 'add-X' 'params',
              which is sufficient to generate DB key.

        :param req_key:     The Request key to get params for.

        :returns: the parameters of the correspondent request key.
        """
        if not req_key in self.db:
            return None
        return self.db[req_key].get('params')

    def get_request_cmd_list(self, req_key):
        """Retrives translation of the request to list of commands.

        :param request: The request as it would be received on network,
                        including name (request['message']) and parmateres
                        (request['params']) if exist.

        :returns: the tuple of the command list and the 'executed' flag
        """
        if not req_key in self.db:
            return (None, None)
        return (self.db[req_key].get('cmd_list'), self.db[req_key].get('executed'))

    def exists(self, req_key):
        """Check if entry exists in DB.

        :param request: the configuration request as it would be received from flexiManage

        :returns: 'True' if request exists and 'False' otherwise.
        """
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

    def update_signature(self, request):
        """Updates the database signature.
        This function assists the database synchronization feature that keeps
        the configuration set by user on the flexiManage in sync with the one
        stored on the flexiEdge device.
            The initial signature of the database is empty string. Than on every
        successfully handled request it is updated according following formula:
                signature = sha1(signature + request)
        where both signature and delta are strings.

        :param request: the last successfully handled router configuration
                        request, e.g. add-interface, remove-tunnel, etc.
                        As configuration database signature should reflect
                        the latest configuration, it should be updated with this
                        request.
        """
        current     = self.db['signature']
        delta       = json.dumps(request, separators=(',', ':'), sort_keys=True)
        hash_object = hashlib.sha1(current + delta)
        new         = hash_object.hexdigest()

        self.db['signature'] = new
        fwglobals.log.debug("sha1: new=%s, current=%s, delta=%s" %
                            (str(new), str(current), str(delta)))

    def get_signature(self):
        """Retrives signature of the current configuration.
        The signature is SHA-1 based hash on requests store in local database.

        :returns: the signature as a string.
        """
        if not 'signature' in self.db:
            self.reset_signature()
        return self.db['signature']

    def reset_signature(self, new_signature=None, log=True):
        """Resets configuration signature to the empty sting.

        :param new_signature: string to be used as a signature of the configuration.
                        If not provided, the empty string will be used.
                        When flexiManage detects discrepancy between this signature
                        and between signature that it calculated, it sends
                        the 'sync-device' request in order to apply the user
                        configuration onto device. On successfull sync the signature
                        is reset to the empty string on both sides.
        :param log: if False the reset will be not logged.
        """
        old_signature = self.db.get('signature', '<none>')
        new_signature = "" if new_signature == None else new_signature
        self.db['signature'] = new_signature
        if log:
            fwglobals.log.debug("reset signature: '%s' -> '%s'" % \
                                (old_signature, new_signature))
