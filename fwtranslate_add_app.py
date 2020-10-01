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

from netaddr import *

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
#            "serviceClass":"dns",
#            "priority":3,
#            "rules":[{
#              "ip":"8.8.8.8/32",
#              "ports":"53"
#              },
#              {
#              "ip":"8.8.4.4/32",
#              "ports":"53"}]
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


proto_map = {'icmp':1, 'tcp':6, 'udp':17}

def add_acl_rule(rule, rules):
    """Add ACL rule.

     :param rule:       Rule field.
     :param rules:      Rules list.

     :returns: None.
     """
    # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
    ip_prefix = 0
    ip_bytes = '\x00\x00\x00\x00'
    proto = None
    port_from = 0
    port_to = 65535

    protocol = rule.get('protocol', None)
    if protocol:
        proto = [ proto_map[rule['protocol']] ]

    ip = rule.get('ip', None)
    if ip:
        ip_network = IPNetwork(rule['ip'])
        ip_bytes, _ = fwutils.ip_str_to_bytes(str(ip_network.ip))
        ip_prefix = ip_network.prefixlen

    ports = rule.get('ports', None)
    if ports:
        ports_map = map(int, ports.split('-'))
        port_from = port_to = ports_map[0]
        if len(ports_map) > 1:
            port_to = ports_map[1]

        # If ports were provided, ensure non-zero protocol in rule.
        # The zero protocol in rule causes VPP/ACL to ignore ports at all,
        # so rule matches any ports!
        # Most likely this is not what user expected to happen.
        #
        if not proto:
            proto = [ proto_map['udp'] , proto_map['tcp'] ]

    # If no protocol was provided, use ANY
    #
    if not proto:
        proto = [ 0 ]

    for p in proto:
        rules.append(_create_rule(is_ipv6=0, is_permit=1,
                                dport_from=port_from,
                                dport_to=port_to,
                                d_prefix=ip_prefix,
                                proto=p,
                                d_ip=ip_bytes))

        rules.append(_create_rule(is_ipv6=0, is_permit=1,
                                sport_from=port_from,
                                sport_to=port_to,
                                s_prefix=ip_prefix,
                                proto=p,
                                s_ip=ip_bytes))

def _add_acl(params, cmd_list, cache_key):
    """Generate ACL command.

     :param params:        Parameters from flexiManage.
     :param cmd_list:      Commands list.

     :returns: None.
     """
    rules = []

    for rule in params['rules']:
        add_acl_rule(rule, rules)

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

def _add_app_info(params, cmd_list, cache_key):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    new_params = copy.deepcopy(params)
    new_params['substs'] = [ { 'add_param':cache_key, 'val_by_key':cache_key} ]


    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']      = "python"
    cmd['cmd']['descr']     = "Add APP %s" % (params['id'])
    cmd['cmd']['params']    = {
                'object': 'fwglobals.g.apps',
                'func':   'add_remove_application',
                'args': {
                    'add':          True,
                    'id':           params['id'],
                    'category':     params.get('category'),
                    'serviceClass': params.get('serviceClass'),
                    'importance':   params.get('importance')
                },
                'substs': [ { 'add_param':cache_key, 'val_by_key':cache_key} ]
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "Delete APP %s" % (params['id'])
    cmd['revert']['params'] = {
                'object': 'fwglobals.g.apps',
                'func':   'add_remove_application',
                'args': {
                    'add':          False,
                    'id':           params['id'],
                    'category':     params.get('category'),
                    'serviceClass': params.get('serviceClass'),
                    'importance':   params.get('importance')
                },
                'substs': [ { 'add_param':cache_key, 'val_by_key':cache_key} ]
    }
    cmd_list.append(cmd)

def add_app(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []

    for app in params['applications']:
        _add_acl(app, cmd_list, 'acl_index')
        _add_app_info(app, cmd_list, 'acl_index')

    return cmd_list

def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
