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

import copy
import os
import re

import fwglobals
import fwtranslate_revert
import fwutils

# add-multilink-policy
# --------------------------------------
# Translates request:
#
# {
#    "entity": "agent",
#    "message": "add-multilink-policy",
#    "params": {
#        "id": "5e8d7d5305369313f5ceff5b",
#        "rules": [
#            {
#                "action": {
#                    "fallback": "by-destination",
#                    "links": [
#                        {
#                            "order": "priority",
#                            "pathlabels": [
#                                "5e8d7cc005369313f5ceff16"
#                            ]
#                        }
#                    ],
#                    "order": "priority"
#                },
#                "classification": {
#                    "application": {
#                        "category": "office",
#                        "importance": "",
#                        "name": "",
#                        "serviceClass": ""
#                    },
#                    "prefix": {}
#                },
#                "id": "5e8d7d5305369313f5ceff5c",
#                "priority": 0
#            }
#        ]
#    }
# }

def _add_policy_rule(params, policy_id, cmd_list):
    """Translates single policy rule into commands to be applied to VPP.

     :param params:    policy rule parameters received from flexiManage.
     :param cmd_list:  list of policy commands where the rule commands should be added to.

     :returns: Updated list of commands.
     """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add rule (id=%d) to policy (id=%d)" % (params['id'], policy_id)
    cmd['cmd']['params']  = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'rule': params, 'policy-id': policy_id, 'remove': False }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove rule (id=%d) to policy (id=%d)" % (params['id'], policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'rule': params, 'policy-id': policy_id, 'remove': True }
    }
    cmd_list.append(cmd)
    return cmd_list

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for rule in params['rules']:
        _add_policy_rule(rule, params['id'], cmd_list)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy:%s' % params['id']
