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
import ctypes
import os
import re
import time

import fwglobals
import fwtranslate_revert
import fwutils
from fwtranslate_add_app import add_acl_rule

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

policy_index = 0

def _generate_id(ret):
    """Generate identifier.

    :param ret:         Initial id value.

    :returns: identifier.
    """
    ret += 1
    if ret == 2 ** 32:  # sad_id is u32 in VPP
        ret = 0
    return ret

def _generate_policy_id():
    """Generate policy identifier.

    :returns: New policy identifier.
    """
    global policy_index
    policy_index = _generate_id(policy_index)
    return copy.deepcopy(policy_index)

def reset_policy_id():
    """Reset policy identifier.
    """
    global policy_index
    policy_index = 0

def _add_policy_rule(policy_id, priority, links, acl_id, fallback, order, cmd_list):
    """Translates single policy rule into commands to be applied to VPP.

     :param params:    policy rule parameters received from flexiManage.
     :param cmd_list:  list of policy commands where the rule commands should be added to.

     :returns: Updated list of commands.
     """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add policy (id=%d)" % (policy_id)
    cmd['cmd']['params']  = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'add': True, 'links': links, 'policy_id': policy_id,
                                'fallback': fallback, 'order': order, 'acl_id': acl_id,
                                'priority': priority}
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'add': False, 'links': links, 'policy_id': policy_id,
                                'fallback': fallback, 'order': order, 'acl_id': acl_id,
                                'priority': priority}
    }
    cmd_list.append(cmd)
    return cmd_list

def _add_policy_rule_from_cache_key(policy_id, priority, links, cache_key, fallback, order, cmd_list):
    """Translates single policy rule into commands to be applied to VPP.

     :param params:    policy rule parameters received from flexiManage.
     :param cmd_list:  list of policy commands where the rule commands should be added to.

     :returns: Updated list of commands.
     """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add policy (id=%d)" % (policy_id)
    cmd['cmd']['params']  = {
                    'module': 'fwutils',
                    'func':   'vpp_multilink_update_policy_rule',
                    'args'  : { 'add': True, 'links': links, 'policy_id': policy_id,
                                'fallback': fallback, 'order': order, 'priority': priority },
                    'substs' : [{'add_param': 'acl_id', 'val_by_key': cache_key}]
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func':   'vpp_multilink_update_policy_rule',
                    'args'  : { 'add': False, 'links': links, 'policy_id': policy_id,
                                'fallback': fallback, 'order': order, 'priority': priority },
                    'substs' : [{'add_param': 'acl_id', 'val_by_key': cache_key}]
    }
    cmd_list.append(cmd)
    return cmd_list

def _add_acl(params, cmd_list, cache_key):
    """Generate ACL command.

     :param params:        Parameters from flexiManage.
     :param cmd_list:      Commands list.

     :returns: None.
     """
    rules = []

    add_acl_rule(params, rules)

    add_params = {
        'acl_index': ctypes.c_uint(-1).value,
        'count': len(rules),
        'r': rules,
        'tag': ''
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "acl_add_replace"
    cmd['cmd']['params'] = add_params
    cmd['cmd']['cache_ret_val'] = (cache_key, cache_key)
    cmd['cmd']['descr'] = "Add ACL"
    cmd['revert'] = {}
    cmd['revert']['name'] = "acl_del"
    cmd['revert']['params'] = {'substs': [ { 'add_param':cache_key, 'val_by_key':cache_key} ]}
    cmd['revert']['descr'] = "Remove ACL"
    cmd_list.append(cmd)

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    policy_acl_ids = set()

    for rule in params['rules']:
        priority = rule['priority']
        fallback = rule['action'].get('fallback', 'by-destination')
        order    = rule['action'].get('order', 'priority')
        links    = rule['action']['links']

        classification = rule['classification']
        app = classification.get('application', None)
        prefix = classification.get('prefix', None)

        if prefix:
            _add_acl(prefix, cmd_list, 'acl_index')
            policy_id = _generate_policy_id()
            _add_policy_rule_from_cache_key(policy_id, priority, links, 'acl_index', fallback, order, cmd_list)

        elif app:
            id = app.get('appId', None)
            category = app.get('category', None)
            service_class = app.get('serviceClass', None)
            importance = app.get('importance', None)

            rule_acl_ids = fwglobals.g.apps.acl_ids_get(id, category, service_class, importance)

            for acl_id in rule_acl_ids:
                if acl_id in policy_acl_ids:
                    continue
                policy_id = _generate_policy_id()
                _add_policy_rule(policy_id, priority, links, acl_id, fallback, order, cmd_list)
                policy_acl_ids.add(acl_id)

        else:
            policy_id = _generate_policy_id()
            _add_policy_rule(policy_id, priority, links, None, fallback, order, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy'
