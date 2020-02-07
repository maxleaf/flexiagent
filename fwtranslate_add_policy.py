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
# {
#      "entity":  "agent",
#      "message": "add-policy",
#      "params": {
#             "app":"google-dns",
#             "pci": "0000:00:08.00",
#             "route":
#             {
#               "via": "10.100.0.6"
#             }
#        }
# }

def _add_policy(app, policy_id, acl_id, ip, cmd_list):
    """Generate add policy command.

     :param app:        Application name.
     :param policy_id:  Policy id.
     :param acl_id:     ACL id.
     :param ip:         Ip address.
     :param cmd_list:   Commands list.

     :returns: List of commands.
     """
    paths = _encode_paths(ip)

    rule = ({'policy_id': policy_id,
             'acl_index': acl_id,
             'paths'    : paths,
             'n_paths': len(paths)})

    cmd_params = {
            'is_add'           : 1,
            'policy'           : rule
    }

    # abf.api.json: abf_policy_add_del (is_add, ..., <type vl_api_abf_policy_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "abf_policy_add_del"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Add ABF for app %s" % (app)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'abf_policy_add_del'
    cmd['revert']['params']     = copy.deepcopy(cmd_params)
    cmd['revert']['params']['is_add'] = 0
    cmd['revert']['descr']      = "Delete ABF for app %s" % (app)
    cmd_list.append(cmd)

    return cmd_list

def _attach_policy(sw_if_index, app, policy_id, priority, is_ipv6, cmd_list):
    """Generate add policy command.

     :param sw_if_index: Interface index.
     :param app:         Application name.
     :param policy_id:   Policy id.
     :param priority:    Priority.
     :param is_ipv6:     IPv6 flag.
     :param cmd_list:    Commands list.

     :returns: List of commands.
    """
    attach = ({'policy_id': policy_id,
               'sw_if_index': sw_if_index,
               'priority': priority,
               'is_ipv6': is_ipv6})

    cmd_params = {
            'is_add'           : 1,
            'attach'           : attach
    }

    # abf.api.json: abf_itf_attach_add_del (is_add, ..., <type vl_api_abf_itf_attach_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "abf_itf_attach_add_del"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Attach ABF for app %s" % (app)
    cmd['revert'] = {}
    cmd['revert']['name']       = 'abf_itf_attach_add_del'
    cmd['revert']['params']     = copy.deepcopy(cmd_params)
    cmd['revert']['params']['is_add'] = 0
    cmd['revert']['descr']      = "Attach ABF for app %s" % (app)
    cmd_list.append(cmd)

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    app = ""
    category = ""
    subcategory = ""
    priority = -1

    if 'app' in params:
        app = params['app']

    if 'category' in params:
        category = params['category']

    if 'subcategory' in params:
        subcategory = params['subcategory']

    if 'priority' in params:
        priority = params['priority']

    ip_bytes, ip_len = fwutils.ip_str_to_bytes(params['route']['via'])

    cmd_params = {
            'id': params['id'],
            'app': app,
            'category': category,
            'subcategory': subcategory,
            'priority': priority,
            'pci': params['pci'],
            'next_hop': ip_bytes
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "add-policy-info"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Add policy %d" % (params['id'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'remove-policy-info'
    cmd['revert']['params']     = cmd_params
    cmd['revert']['descr']      = "Delete policy %d" % (params['id'])
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-policy:%s' % params['id']
