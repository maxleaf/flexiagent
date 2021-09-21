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

import os
import re
import ctypes
import copy

import fwglobals
import fwtranslate_revert
import fwutils

import netaddr

# add-application
# --------------------------------------
# Translates request:
# {
#   "entity":  "agent",
#   "message": "add-application",
#   "params": [{
#            "app":"google-dns",
#            "id":1,
#            "category":"network",
#            "serviceClass":"dns",
#            "priority":3,
#            "rules":[{
#              "ip":"8.8.8.8/32",
#              "ports":"53"
#              },
#              {
#              "ip":"8.8.4.4/32",
#              "ports":"53"}]
#            }]
# }
def _add_traffic_identification(params, cmd_list):

    cmd = {}

    cmd['cmd'] = {}
    cmd['cmd']['name'] = "python"
    cmd['cmd']['descr'] = "Add Traffic Identification %s" % (params['id'])
    cmd['cmd']['params'] = {
                'object': 'fwglobals.g.traffic_identifications',
                'func':   'add_traffic_identification',
                'args': {
                    'traffic':      params
                }
    }

    cmd['revert'] = {}
    cmd['revert']['name'] = "python"
    cmd['revert']['descr'] = "Delete Traffic Identification %s" % (params['id'])
    cmd['revert']['params'] = {
                'object': 'fwglobals.g.traffic_identifications',
                'func':   'remove_traffic_identification',
                'args': {
                    'traffic':      params
                }
    }
    cmd_list.append(cmd)

def add_app(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for app in params['applications']:
        _add_traffic_identification(app, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
