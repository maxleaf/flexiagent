#! /usr/bin/python3

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

import fwglobals
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
#            },
#            {
#                "id": "2",
#                "priority": 0,
#                "classification": {
#                "prefix": {
#                    "ip": "8.8.8.8/32",
#                    "ports": "",
#                    "protocol": ""
#                }
#                },
#                "action": {
#                "links": [
#                    {
#                    "pathlabels": [ "green" , "blue" ],
#                    "order": "load-balance"
#                    },
#                    {
#                    "pathlabels": [ "blue" ],
#                    "order": "priority"
#                    }
#                ],
#                "order": "load-balance",
#                "fallback": "by-destination"
#                }
#            },
#            ...
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

def _traffic_to_acl_rules(rules):
    """Converts list of traffic identification rules into list of ACL matching rules.

    :param rules:  list of traffic identification rules.
                   These rules are taken from within 'add-application' requests.
                   We use 'traffic identification' term to denote applications
                   that packets might belong to. So the traffic identification
                   rules are application matching rules. Every application
                   in the 'add-application' request might have list of matching
                   rules:

                    {
                        "entity": "agent",
                        "message": "add-application",
                        "params": {
                            "applications": [
                            {
                                "name": "daytime",
                                "id": "3",
                                "category": "management",
                                "serviceClass": "network-control",
                                "importance": "high",
                                "description": "Daytime Protocol",
                                "rules": [
                                {
                                    "protocol": "tcp",
                                    "ports": "18"
                                },
                                {
                                    "protocol": "udp",
                                    "ports": "28"
                                }
                                ],
                                "modified": true
                            },
                            {
                                "name": "new_ssh",
                                "id": "55",
                                "category": "remote_access",
                                "serviceClass": "default",
                                "importance": "low",
                                "description": "New Secure Shell (NSSH)",
                                "rules": [
                                {
                                    "protocol": "tcp",
                                    "ports": "22"
                                }
                        ...


    :returns: list of ACL matching rules.
              These rules reflect the application matching rules and they
              are provided to the acl_add_replace() VPP API in order to
              create ACL object that filters packets that are subject for policy.
    """
    acl_rules = []
    for traffic_rule in rules:

        proto = None
        port_from = 0
        port_to = 65535

        protocol = traffic_rule.get('protocol', None)
        if protocol:
            proto = [ fwutils.proto_map[protocol] ]

        ip_prefix = traffic_rule.get('ip', '0.0.0.0/0')

        ports = traffic_rule.get('ports', None)
        if ports:
            ports_map = list(map(int, ports.split('-')))
            port_from = port_to = ports_map[0]
            if len(ports_map) > 1:
                port_to = ports_map[1]

        if not proto:
            proto = [ fwutils.proto_map['any'] ] if not ports else \
                    [ fwutils.proto_map['udp'] , fwutils.proto_map['tcp'] ]

        for p in proto:
            acl_rules.append({
                'is_permit': 1, 'is_ipv6': 0, 'proto': p,
                'srcport_or_icmptype_first': 0,
                'srcport_or_icmptype_last': 65535,
                'src_prefix': '0.0.0.0/0',
                'dstport_or_icmpcode_first': port_from,
                'dstport_or_icmpcode_last': port_to,
                'dst_prefix': ip_prefix
            })
            acl_rules.append({
                'is_permit': 1, 'is_ipv6': 0, 'proto': p,
                'srcport_or_icmptype_first': port_from,
                'srcport_or_icmptype_last': port_to,
                'src_prefix': ip_prefix,
                'dstport_or_icmpcode_first': 0,
                'dstport_or_icmpcode_last': 65535,
                'dst_prefix': '0.0.0.0/0'
            })
    return acl_rules


def add_multilink_policy(params):
    """Translates the received from flexiManage 'add-multilink-policy' request
    into list of commands to be executed in order to configure policy in VPP.

    :param params: the 'params' section of the 'add-multilink-policy' request.

    :returns: List of commands.
    """
    cmd_list = []
    cache_key = 'multilink-acl-index'

    # Every rule in the received 'add-multilink-policy' request creates Policy object in VPP

    for rule in params['rules']:

        # Build translation that creates ACL object in VPP.
        # The ACL might have a list of matching rules. The matching rules are
        # generated out of the policy 'classification' parameter.
        # The classification can include either ID of specific application ('appId')
        # or an implicit set of applications marked by category/serviceClass/importance.
        # Note even if specific application was provided by the classification,
        # we still might generate a list of matching rules, as application might
        # have multiple matching rules. The application matching rules are called
        # traffic identification rules. So we gather traffic identification rules
        # for all applications classified by this policy, than we convert these
        # rules into list of ACL matching rules that later will be feed into the
        # single ACL object that will serve the policy.
        #
        traffic_rules = []

        prefix = rule['classification'].get('prefix')
        if prefix:
            traffic_rules = [ prefix ]
        else:
            app = rule['classification']['application']
            traffic_id         = app.get('appId')
            traffic_category   = app.get('category')
            traffic_class      = app.get('serviceClass')
            traffic_importance = app.get('importance')

            traffic_rules = fwglobals.g.traffic_identifications.get_traffic_rules(
                                traffic_id, traffic_category, traffic_class, traffic_importance)

        acl_rules = _traffic_to_acl_rules(traffic_rules)

        # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "acl_add_replace"
        cmd['cmd']['params'] = {
                                'acl_index': ctypes.c_uint(-1).value,
                                'count':     len(acl_rules),
                                'r':         acl_rules,
                                'tag':       ''
        }
        cmd['cmd']['cache_ret_val'] = ('acl_index', cache_key)
        cmd['cmd']['descr'] = f"add ACL for policy {rule['id']}"
        cmd['revert'] = {}
        cmd['revert']['name'] = "acl_del"
        cmd['revert']['params'] = {'substs': [ { 'add_param':'acl_index', 'val_by_key':cache_key} ]}
        cmd['revert']['descr'] = f"remove ACL for policy {rule['id']}"
        cmd_list.append(cmd)

        # Now build translation that creates Policy object in VPP.
        #
        priority  = rule['priority']
        fallback  = rule['action'].get('fallback', 'by-destination')
        order     = rule['action'].get('order', 'priority')
        links     = rule['action']['links']
        policy_id = _generate_policy_id()

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = f"add policy (id={policy_id}, {rule['id']})"
        cmd['cmd']['params']  = {
                        'module': 'fwutils',
                        'func':   'vpp_multilink_update_policy_rule',
                        'args'  : { 'add': True, 'links': links, 'policy_id': policy_id,
                                    'fallback': fallback, 'order': order, 'priority': priority },
                        'substs' : [{'add_param': 'acl_id', 'val_by_key': cache_key}]
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = f"remove policy (id={policy_id}, {rule['id']})"
        cmd['revert']['params'] = {
                        'module': 'fwutils',
                        'func':   'vpp_multilink_update_policy_rule',
                        'args'  : { 'add': False, 'links': links, 'policy_id': policy_id,
                                    'fallback': fallback, 'order': order, 'priority': priority },
                        'substs' : [{'add_param': 'acl_id', 'val_by_key': cache_key}]
        }
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy'
