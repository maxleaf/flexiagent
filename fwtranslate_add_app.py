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
import ctypes
import copy

import fwglobals
import fwtranslate_revert
import fwutils

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
#            "subcategory":"dns",
#            "priority":3,
#            "rules":[{
#              "ip":"8.8.8.8",
#              "ip-prefix":32,
#              "port-range-low":53,
#              "port-range-high":53},
#              {
#              "ip":"8.8.4.4",
#              "ip-prefix":32,
#              "port-range-low":53,
#              "port-range-high":53}]
#            }]
# }
def _create_rule(is_ipv6=0, is_permit=0, proto=0,
                 sport_from=0, sport_to=65535,
                 s_prefix=0, s_ip='\x00\x00\x00\x00',
                 dport_from=0, dport_to=65535,
                 d_prefix=0, d_ip='\x00\x00\x00\x00'):
    rule = ({'is_permit': is_permit, 'is_ipv6': is_ipv6, 'proto': proto,
             'srcport_or_icmptype_first': sport_from,
             'srcport_or_icmptype_last': sport_to,
             'src_ip_prefix_len': s_prefix,
             'src_ip_addr': s_ip,
             'dstport_or_icmpcode_first': dport_from,
             'dstport_or_icmpcode_last': dport_to,
             'dst_ip_prefix_len': d_prefix,
             'dst_ip_addr': d_ip})
    return rule

def _add_acl(params, cmd_list, cache_key):
    """Generate ACL command.

     :param params:        Parameters from flexiManage.
     :param cmd_list:      Commands list.

     :returns: None.
     """
    # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
    rules = []

    for rule in params['rules']:
        ip_bytes, ip_len = fwutils.ip_str_to_bytes(rule['ip'])

        rules.append(_create_rule(is_ipv6=0, is_permit=1,
                                  dport_from=rule['port-range-low'],
                                  dport_to=rule['port-range-high'],
                                  d_prefix=rule['ip-prefix'],
                                  proto=rule['proto'],
                                  d_ip=ip_bytes))

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
    cmd['cmd']['descr'] = "Add ACL for app %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name'] = "acl_del"
    cmd['revert']['params'] = {'substs': [ { 'add_param':cache_key, 'val_by_key':cache_key} ]}
    cmd['revert']['descr'] = "Remove ACL for app %s" % (params['app'])
    cmd_list.append(cmd)

def _add_app_info(params, cmd_list, cache_key):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    new_params = copy.deepcopy(params)
    new_params['substs'] = [ { 'add_param':cache_key, 'val_by_key':cache_key} ]

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "add-app-info"
    cmd['cmd']['params']        = new_params
    cmd['cmd']['descr']         = "Add APP %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'remove-app-info'
    cmd['revert']['params']     = new_params
    cmd['revert']['descr']      = "Delete APP %s" % (params['app'])
    cmd_list.append(cmd)

def add_app(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    _add_acl(params, cmd_list, 'acl_index')
    _add_app_info(params, cmd_list, 'acl_index')

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application:%s' % params['id']
