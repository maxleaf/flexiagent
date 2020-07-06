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

def _add_policy_rule(policy_id, links, acl_id, fallback, order, cmd_list):
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
                    'args'  : { 'links': links, 'policy_id': policy_id,
                                'acl_id': acl_id, 'fallback': fallback,
                                'order': order, 'remove': False }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'links': links, 'policy_id': policy_id,
                                'acl_id': acl_id, 'fallback': fallback,
                                'order': order, 'remove': True }
    }
    cmd_list.append(cmd)
    return cmd_list

def _add_policy_rule_from_cache_key(policy_id, links, cache_key, fallback, order, cmd_list):
    """Translates single policy rule into commands to be applied to VPP.

     :param params:    policy rule parameters received from flexiManage.
     :param cmd_list:  list of policy commands where the rule commands should be added to.

     :returns: Updated list of commands.
     """

    add_args = {
        'substs' : [{'add_param': 'acl_id', 'val_by_key': cache_key}],
        'links': links,
        'policy_id': policy_id,
        'fallback': fallback,
        'order': order,
        'remove': False
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "add-policy-info"
    cmd['cmd']['descr']   = "add policy (id=%d)" % (policy_id)
    cmd['cmd']['params']  = add_args

    remove_args = copy.deepcopy(add_args)
    remove_args['remove'] = True

    cmd['revert'] = {}
    cmd['revert']['name']   = "remove-policy-info"
    cmd['revert']['descr']  = "remove policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = remove_args

    cmd_list.append(cmd)
    return cmd_list

def _attach_policy(int_name, policy_id, priority, is_ipv6, cmd_list):
    """Generate attach policy command.

     :param int_name:    Interface name.
     :param policy_id:   Policy id.
     :param priority:    Priority.
     :param is_ipv6:     IPv6 flag.
     :param cmd_list:    Commands list.

     :returns: List of commands.
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "attach policy (id=%d)" % (policy_id)
    cmd['cmd']['params']  = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_attach_policy_rule',
                    'args'  : { 'int_name': int_name, 'policy_id': policy_id, 'priority': priority, 'is_ipv6': is_ipv6, 'remove': False}
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "detach policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_attach_policy_rule',
                    'args'  : { 'int_name': int_name, 'policy_id': policy_id, 'priority': priority, 'is_ipv6': is_ipv6, 'remove': True}
    }
    cmd_list.append(cmd)

def _attach_policy_lans_loopbacks(policy_id, priority, lan_pci_list, loopback_ip_list, cmd_list):
    """Generate attach policy commands.

     :param policy_id:   Policy id.
     :param priority:    Priority.
     :param cmd_list:    Commands list.

     :returns: List of commands.
    """
    is_ipv6 = 0

    for int_name in lan_pci_list:
        _attach_policy(int_name, policy_id, priority, is_ipv6, cmd_list)

    for int_name in loopback_ip_list:
        _attach_policy(int_name, policy_id, priority, is_ipv6, cmd_list)

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
    lan_pci_list = fwglobals.g.router_api.get_pci_lan_interfaces()
    loopback_ip_list = fwglobals.g.router_api.get_ip_tunnel_interfaces()

    policy_acl_ids = set()


    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['descr']  = "remove-multilink-policy"
    cmd['cmd']['params'] = {
                            'object': 'fwglobals.g',
                            'func'  : 'handle_request',
                            'args'  : {
                                'req'   : 'remove-multilink-policy',
                                'params': None,
                                'result': None
                            }
                           }
    cmd_list.append(cmd)

    for rule in params['rules']:
        priority = rule['priority']
        fallback = rule['action']['fallback']
        order = rule['action']['order']
        links = rule['action']['links']

        classification = rule['classification']
        app = classification.get('application', None)
        prefix = classification.get('prefix', None)

        if prefix:
            _add_acl(prefix, cmd_list, 'acl_index')
            policy_id = _generate_policy_id()
            _add_policy_rule_from_cache_key(policy_id, links, 'acl_index', fallback, order, cmd_list)
            _attach_policy_lans_loopbacks(policy_id, priority, lan_pci_list, loopback_ip_list, cmd_list)

        elif app:
            id = app.get('appId', None)
            category = app.get('category', None)
            service_class = app.get('serviceClass', None)
            importance = app.get('importance', None)

            rule_acl_ids = fwglobals.g.apps_api.acl_ids_get(id, category, service_class, importance)

            for acl_id in rule_acl_ids:
                if acl_id in policy_acl_ids:
                    continue
                policy_id = _generate_policy_id()
                _add_policy_rule(policy_id, links, acl_id, fallback, order, cmd_list)
                _attach_policy_lans_loopbacks(policy_id, priority, lan_pci_list, loopback_ip_list, cmd_list)
                policy_acl_ids.add(acl_id)

        else:
            policy_id = _generate_policy_id()
            _add_policy_rule(policy_id, links, None, fallback, order, cmd_list)
            _attach_policy_lans_loopbacks(policy_id, priority, lan_pci_list, loopback_ip_list, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy'
