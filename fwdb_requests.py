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
import os
import re
import yaml

from sqlitedict import SqliteDict

import fwglobals

class FwDbRequests:
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

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for key in self.db:
            self.remove(key)
        self.reset_signature()

    def add(self, key, req, params, cmd_list, executed):
        """Add key-value into DB.

        :param key:           A key.
        :param req:           A request.
        :param params:        Parameters.
        :param cmd_list:      Command list.
        :param executed:      Executed flag.

        :returns: None.
        """
        self.update(key, req, params, cmd_list, executed)

    def remove(self, key):
        """Remove entry from DB.

        :param key:           A key.

        :returns: None.
        """
        del self.db[key]

    def update(self, key, req, params, cmd_list, executed):
        """Update entry in DB.

        :param key:           A key.
        :param req:           A request.
        :param params:        Parameters.
        :param cmd_list:      Command list.
        :param executed:      Executed flag.

        :returns: None.
        """
        self.db[key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed } 

    def fetch_request(self, key):
        """Fetch request from DB.

        :param key:           A key.

        :returns: Request and its parameters.
        """
        if not key in self.db:
            return (None, None) 
        request = self.db[key].get('request')
        params  = self.db[key].get('params')
        return (request, params)

    def fetch_cmd_list(self, key):
        """Fetch commands from DB.

        :param key:           A key.

        :returns: Commands and executed flag.
        """
        cmd_list = self.db[key].get('cmd_list')
        executed = self.db[key]['executed']
        return (cmd_list , executed) 

    def exists(self, key):
        """Check if entry exists in DB.

        :param key:           A key.

        :returns: 'True' if entry exists and 'False' otherwise.
        """
        res = True if key in self.db else False  
        return res

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
                        request, e.g. add-interface, remove-tunnel, modify-device,
                        etc. As configuration database signature should reflect
                        the latest configuration, it should be updated with this
                        request.
        """
        current = self.db['signature']
        if request:
            delta       = json.dumps(request, separators=(',', ''), sort_keys=True)
            hash_object = hashlib.sha1(current + delta)
            new         = hash_object.hexdigest()
        else:
            delta = ""
            new   = ""
        self.db['signature'] = new

        fwglobals.log.debug("fwdb_requests: sha1: new=%s, current=%s, delta=%s" %
                            (str(new), str(current), str(delta)))

    def get_signature(self):
        fwglobals.log.debug("fwdb_requests: get signature: " + self.db['signature'])
        return self.db['signature']

    def reset_signature(self):
        fwglobals.log.debug("fwdb_requests: reset signature")
        self.db['signature'] = ""
