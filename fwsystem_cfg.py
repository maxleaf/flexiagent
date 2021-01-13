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

        return fwutils.dumps_config(cfg, sections, full)
