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

# add-app
# --------------------------------------
# Translates request:
# {
#   "entity":  "agent",
#   "message": "add-app",
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

# traffic types
IP = 0
ICMP = 1

# IP version
IPRANDOM = -1
IPV4 = 0
IPV6 = 1

# rule types
DENY = 0
PERMIT = 1

# supported protocols
proto = [[6, 17], [1, 58]]
proto_map = {1: 'ICMP', 58: 'ICMPv6EchoRequest', 6: 'TCP', 17: 'UDP'}
ICMPv4 = 0
ICMPv6 = 1
TCP = 0
UDP = 1
PROTO_ALL = 0

# port ranges
PORTS_ALL = -1
PORTS_RANGE = 0

# ACL
NEW_ACL_ID = 4294967295

def _create_rule(ip=0, permit_deny=0, proto=0,
                 sport_from=0, sport_to=65535,
                 s_prefix=0, s_ip='\x00\x00\x00\x00',
                 dport_from=0, dport_to=65535,
                 d_prefix=0, d_ip='\x00\x00\x00\x00'):

    rule = ({'is_permit': permit_deny, 'is_ipv6': ip, 'proto': proto,
             'srcport_or_icmptype_first': sport_from,
             'srcport_or_icmptype_last': sport_to,
             'src_ip_prefix_len': s_prefix,
             'src_ip_addr': s_ip,
             'dstport_or_icmpcode_first': dport_from,
             'dstport_or_icmpcode_last': dport_to,
             'dst_ip_prefix_len': d_prefix,
             'dst_ip_addr': d_ip})
    return rule

def _add_acl(params, cmd_list):
    """Generate ACL command.

     :param params:        Parameters from flexiManage.
     :param cmd_list:      Commands list.

     :returns: Cache key of ACL id.
     """
    # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
    rules = []

    for rule in params['rules']:
        ip_bytes, ip_len = fwutils.ip_str_to_bytes(rule['ip'])

        rules.append(_create_rule(ip=IPV4, permit_deny=PERMIT,
                                  dport_from=rule['port-range-low'],
                                  dport_to=rule['port-range-high'],
                                  d_prefix=rule['ip-prefix'],
                                  d_ip=ip_bytes))

    cmd_params = {
            'acl_index'        : NEW_ACL_ID,
            'count'            : len(rules),
            'r'                : rules,
            'tag'              : ''
    }

    ret_attr = 'acl_index'
    cache_key = 'acl_index'
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "acl_add_replace"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['cache_ret_val'] = (ret_attr, cache_key)
    cmd['cmd']['descr']         = "Add ACL for app %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'acl_del'
    cmd['revert']['params']     = {'substs': [ { 'add_param':ret_attr, 'val_by_key':cache_key} ]}
    cmd['revert']['descr']      = "Delete ACL for app %s" % (params['app'])
    cmd_list.append(cmd)

    return cache_key

def _add_app(params, cache_key, cmd_list):
    """Generate APP in DB.

     :param params:        Parameters from flexiManage.
     :param cache_key:     ACL id cache key.
     :param cmd_list:      Commands list.

     """
    cmd_params = {
            'substs': [ { 'add_param':cache_key, 'val_by_key':cache_key} ],
            'app': params['app'],
            'id': params['id'],
            'category': params['category'],
            'subcategory': params['subcategory'],
            'priority': params['priority']
    }
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "save-app-info"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Add APP %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'remove-app-info'
    cmd['revert']['params']     = cmd_params
    cmd['revert']['descr']      = "Delete APP %s" % (params['app'])
    cmd_list.append(cmd)

def add_app(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    acl_id_cache_key = _add_acl(params, cmd_list)
    _add_app(params, acl_id_cache_key, cmd_list)

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-app:%s' % params['id']
