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
import copy

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

def _encode_paths():
    br_paths = []

    label_stack = {'is_uniform': 0,
                   'label': 0,
                   'ttl': 0,
                   'exp': 0}

    label_stack_list = []
    for i in range(16):
        label_stack_list.append(label_stack)

    br_paths.append({'next_hop': b'\x10\x02\x02\xac',
                 'weight'      : 1,
                 'afi'         : 0,
                 'sw_if_index' : 4294967295,
                 'preference'  : 0,
                 'table_id'    : 0,
                 'next_hop_id' : 4294967295,
                 'is_udp_encap': 0,
                 'n_labels'    : 0,
                 'label_stack' : label_stack_list})

    return br_paths

def _create_policy(policy_id, acl_index):

    paths = _encode_paths()

    rule = ({'policy_id': policy_id,
             'acl_index': acl_index,
             'paths'    : paths,
             'n_paths': len(paths)})
    return rule

def _attach_policy(policy_id, sw_if_index, priority, is_ipv6):

     attach = ({'policy_id'   : policy_id,
                'sw_if_index' : sw_if_index,
                'priority'    : priority,
                'is_ipv6'     : is_ipv6})

     return attach

def add_policy(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    cmd_params = {
            'is_add'           : 1,
            'policy'           : _create_policy(1, 0)
    }

    # abf.api.json: abf_policy_add_del (is_add, ..., <type vl_api_abf_policy_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "abf_policy_add_del"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Add ABF for app %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'abf_policy_add_del'
    cmd['revert']['params']     = copy.deepcopy(cmd_params)
    cmd['revert']['params']['is_add'] = 0
    cmd['revert']['descr']      = "Delete ABF for app %s" % (params['app'])
    cmd_list.append(cmd)

    sw_if_index = fwutils.pci_to_vpp_sw_if_index(params['pci'])

    cmd_params = {
            'is_add'           : 1,
            'attach'           : _attach_policy(1, sw_if_index, 0, 0)
    }

    # abf.api.json: abf_itf_attach_add_del (is_add, ..., <type vl_api_abf_itf_attach_t>, ...)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "abf_itf_attach_add_del"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Attach ABF for app %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'abf_itf_attach_add_del'
    cmd['revert']['params']     = copy.deepcopy(cmd_params)
    cmd['revert']['params']['is_add'] = 0
    cmd['revert']['descr']      = "Attach ABF for app %s" % (params['app'])
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-policy:%s' % params['_id']
