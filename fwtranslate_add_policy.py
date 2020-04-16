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

def _add_policy_rule(policy_id, labels, acl_id, cmd_list):
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
                    'args'  : { 'labels': labels, 'policy_id': policy_id, 'acl_id': acl_id, 'remove': False }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_policy_rule',
                    'args'  : { 'labels': labels, 'policy_id': policy_id, 'acl_id': acl_id, 'remove': True }
    }
    cmd_list.append(cmd)
    return cmd_list

def _attach_policy(sw_if_index, policy_id, priority, is_ipv6, cmd_list):
    """Generate attach policy command.

     :param sw_if_index: Interface index.
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
                    'args'  : { 'sw_if_index': sw_if_index, 'policy_id': policy_id, 'priority': priority, 'is_ipv6': is_ipv6, 'remove': False }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "detach policy (id=%d)" % (policy_id)
    cmd['revert']['params'] = {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_attach_policy_rule',
                    'args'  : { 'sw_if_index': sw_if_index, 'policy_id': policy_id, 'priority': priority, 'is_ipv6': is_ipv6, 'remove': True }
    }
    cmd_list.append(cmd)

def _attach_policy_lans(policy_id, priority, cmd_list):
    """Generate attach policy commands.

     :param policy_id:   Policy id.
     :param priority:    Priority.
     :param cmd_list:    Commands list.

     :returns: List of commands.
    """
    is_ipv6 = 0
    interfaces = fwglobals.g.router_api.get_pci_lan_interfaces()

    for pci in interfaces:
        sw_if_index = fwutils.pci_to_vpp_sw_if_index(pci)
        print (sw_if_index)
        _attach_policy(sw_if_index, policy_id, priority, is_ipv6, cmd_list)

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for rule in params['rules']:
        priority = rule['priority']
        links = rule['action']['links']
        labels = links[0]['pathlabels']

        classification = rule['classification']
        app = classification.get('application', None)

        if app:
            name = app.get('name', None)
            category = app.get('category', None)
            service_class = app.get('serviceClass', None)
            importance = app.get('importance', None)

            acl_id_list = fwglobals.g.apps_api.acl_id_list_get(name, category, service_class, importance)
            for acl_id in acl_id_list:
                policy_id = _generate_policy_id()
                _add_policy_rule(policy_id, labels, acl_id, cmd_list)
                _attach_policy_lans(policy_id, priority, cmd_list)

        else:
            policy_id = _generate_policy_id()
            _add_policy_rule(policy_id, labels, None, cmd_list)
            _attach_policy_lans(policy_id, priority, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy:%s' % params['id']
