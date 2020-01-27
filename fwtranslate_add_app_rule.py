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

# add-app-rule
# --------------------------------------
# Translates request:
#
#    "message": "add-app-rule",
#    "params":
#          {"app":"google-dns",
#           "appid":1,
#           "_id":378987465,
#           "ip-range-low":"8.8.8.8",
#           "ip-range-high":"8.8.8.8",
#           "port-range-low":53,
#           "port-range-high":53,
#           "category":"network",
#           "subcategory":"dns",
#           "priority":"3"}
#
#

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
                 d_prefix=32, d_ip='\x08\x08\x08\x08'):

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

def add_app_rule(params):
    """Generate commands ...

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
    cmd_list = []
    rules = []
    rules.append(_create_rule(IPV4, PERMIT))

    cmd_params = {
            'acl_index'        : NEW_ACL_ID,
            'count'            : len(rules),
            'r'                : rules,
            'tag'              : ''
    }

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']          = "acl_add_replace"
    cmd['cmd']['params']        = cmd_params
    cmd['cmd']['descr']         = "Add ACL for app %s" % (params['app'])
    cmd['revert'] = {}
    cmd['revert']['name']       = 'acl_del'
    cmd['revert']['params']     = {'acl_index': params['_id']}
    cmd['revert']['descr']      = "Delete ACL for app %s" % (params['app'])
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return rule key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-app-rule:%s' % params['_id']