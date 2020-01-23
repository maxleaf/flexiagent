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

# add-policy
# --------------------------------------
# Translates request:
#
#git diff
# {
#      "entity":  "agent",
#      "message": "add-policy",
#      "params": {
#            "_id":378987465,
#            "app":"none",
#            "category":"network",
#            "subcategory":"none",
#            "policy":"redirect",
#            "interface_id":"378975625"
#             }
#}
#
#

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-policy:%s' % params['_id']
