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

import fwglobals
import fwtranslate_revert
import fwutils

# add-app-rule
# --------------------------------------
# Translates request:
#
#    "message": "add-app-rule",
#    "params":
#          {"app":"google-dns",
#           "appid":1,
#           "_id":378987465,
#           "ip-range-low":"8.8.8.8",
#           "ip-range-high":"8.8.8.8",
#           "port-range-low":53,
#           "port-range-high":53,
#           "category":"network",
#           "subcategory":"dns",
#           "priority":"3"}
#
#
def add_app_rule(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    return cmd_list

def get_request_key(params):
    """Return rule key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-app-rule:%s' % params['_id']
