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
import re
import ctypes
import copy

import fwglobals
import fwtranslate_revert
import fwutils

# add-app
# --------------------------------------
# Translates request:
# {
#   "entity":  "agent",
#   "message": "add-app",
#   "params": [{
#            "app":"google-dns",
#            "id":1,
#            "category":"network",
#            "subcategory":"dns",
#            "priority":3,
#            "rules":[{
#              "ip":"8.8.8.8",
#              "ip-prefix":32,
#              "port-range-low":53,
#              "port-range-high":53},
#              {
#              "ip":"8.8.4.4",
#              "ip-prefix":32,
#              "port-range-low":53,
#              "port-range-high":53}]
#            }]
# }
def add_app(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "add-app-info"
    cmd['cmd']['params']        = copy.deepcopy(params)
    cmd['cmd']['descr']         = "Add APP %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'remove-app-info'
    cmd['revert']['params']     = copy.deepcopy(params)
    cmd['revert']['descr']      = "Delete APP %s" % (params['app'])
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-app:%s' % params['id']
