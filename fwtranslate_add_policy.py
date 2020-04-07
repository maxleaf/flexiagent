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

# add-policy-multi-link
# --------------------------------------
# Translates request:
#
# {
#      "entity":  "agent",
#      "message": "add-policy-multi-link",
#      "params": {
#             "app":"google-dns",
#             "pci": "0000:00:08.00",
#             "route":
#             {
#               "via": "10.100.0.6"
#             }
#        }
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
    """Generate SA identifier.

    :returns: New SA identifier.
    """
    global policy_index
    policy_index = _generate_id(policy_index)
    return copy.deepcopy(policy_index)


def _encode_paths(next_hop):
    br_paths = []

    label_stack = {'is_uniform': 0,
                   'label': 0,
                   'ttl': 0,
                   'exp': 0}

    label_stack_list = []
    for i in range(16):
        label_stack_list.append(label_stack)

    br_paths.append({'next_hop': next_hop,
                     'weight': 1,
                     'afi': 0,
                     'sw_if_index': 4294967295,
                     'preference': 0,
                     'table_id': 0,
                     'next_hop_id': 4294967295,
                     'is_udp_encap': 0,
                     'n_labels': 0,
                     'label_stack': label_stack_list})

    return br_paths


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
             'paths': paths,
             'n_paths': len(paths)})

    # abf.api.json: abf_policy_add_del (is_add, ..., <type vl_api_abf_policy_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "abf_policy_add_del"
    cmd['cmd']['params'] = {'is_add': 1, 'policy': rule}
    cmd['cmd']['descr'] = "Add ABF for app %s" % (app)
    cmd['revert'] = {}
    cmd['revert']['name'] = 'abf_policy_add_del'
    cmd['revert']['params'] = {'is_add': 0, 'policy': rule}
    cmd['revert']['descr'] = "Remove ABF for app %s" % (app)
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

    # abf.api.json: abf_itf_attach_add_del (is_add, ..., <type vl_api_abf_itf_attach_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name'] = "abf_itf_attach_add_del"
    cmd['cmd']['params'] = {'is_add': 1, 'attach': attach}
    cmd['cmd']['descr'] = "Attach ABF for app %s" % (app)
    cmd['revert'] = {}
    cmd['revert']['name'] = "abf_itf_attach_add_del"
    cmd['revert']['params'] = {'is_add': 0, 'attach': attach}
    cmd['revert']['descr'] = "Detach ABF for app %s" % (app)
    cmd_list.append(cmd)

def _add_policy_info(params, cmd_list):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "add-policy-info"
    cmd['cmd']['params']        = params
    cmd['cmd']['descr']         = "Add policy %d" % (params['id'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'remove-policy-info'
    cmd['revert']['params']     = params
    cmd['revert']['descr']      = "Delete policy %d" % (params['id'])
    cmd_list.append(cmd)

    return cmd_list

def _create_policy_commands(pci, app, category, service_class, importance, next_hop, cmd_list):
    acl_id_list = fwglobals.g.apps_api.acl_id_list_get(app, category, service_class, importance)
    sw_if_index = fwutils.pci_to_vpp_sw_if_index(pci)

    for acl_id in acl_id_list:
        priority = 0
        is_ipv6 = 0
        policy_id = _generate_policy_id()

        _add_policy(app, policy_id, acl_id, next_hop, cmd_list)
        _attach_policy(sw_if_index, app, policy_id, priority, is_ipv6, cmd_list)

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for rule in params['rules']:
        application = rule['classification'].get('application', None)
        if application:
            app = application.get('name', None)
            category = application.get('category', None)
            service_class = application.get('serviceClass', None)
            importance = application.get('importance', None)
        action = rule.get('action', None)

        if action:
            pci = action.get('pci', None)
            next_hop, ip_len = fwutils.ip_str_to_bytes(action['route']['via'])

        _create_policy_commands(pci, app, category, service_class, importance, next_hop, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-policy-multi-link:%s' % params['id']
