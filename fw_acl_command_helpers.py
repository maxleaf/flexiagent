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
import fw_traffic_identification

from netaddr import IPNetwork

def _convert_match_to_acl_param(rule):

    ip = rule.get('ip')
    if ip:
        ip_network = IPNetwork(rule['ip'])
        ip_bytes, _ = fwutils.ip_str_to_bytes(str(ip_network.ip))
        ip_prefix = ip_network.prefixlen
    else:
        ip_bytes = '\x00\x00\x00\x00'
        ip_prefix = 0

    proto = rule.get('protocol')
    ports = rule.get('ports')

    if ports:
        port_from, port_to = fwutils.ports_str_to_range(ports)
        if proto:
            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception('Invalid input with ports but Protocol is not tcp or udp ' % proto)
            proto = [fwutils.proto_map[proto]]
        else:
            proto = [fwutils.proto_map['tcp'], fwutils.proto_map['udp']]
        return ip_bytes, ip_prefix, port_from, port_to, proto
    else:
        return ip_bytes, ip_prefix, 0, 0, [fwutils.proto_map[proto]] if proto else None

def _build_vpp_acl_params(source_match, dest_match, permit, is_ingress):

    rules = []
    src_ip_bytes, src_ip_prefix, src_port_from, src_port_to, src_proto =\
        _convert_match_to_acl_param(source_match)
    dest_ip_bytes, dest_ip_prefix, dest_port_from, dest_port_to, dst_proto =\
        _convert_match_to_acl_param(dest_match)
    if dst_proto is None:
        dst_proto = [0]

    # Protocol is not expected to be present in a valid source match
    # Check and log source and destination protocol mismatch
    if src_proto:
        src_proto.sort()
        dst_proto.sort()
        if src_proto != dst_proto:
            fwglobals.log.warning('Mismatch between src (%s) and dest (%s) protocol fields'
                % (src_proto, dst_proto))

    for p in dst_proto:
        if is_ingress:
            rules.append({'is_permit': int(permit == True),
                      'is_ipv6': 0,
                      'src_ip_addr': src_ip_bytes,
                      'src_ip_prefix_len': src_ip_prefix,
                      'dst_ip_addr': dest_ip_bytes,
                      'dst_ip_prefix_len': dest_ip_prefix,
                      'proto': p,
                      'srcport_or_icmptype_first': src_port_from,
                      'srcport_or_icmptype_last': src_port_to,
                      'dstport_or_icmpcode_first': dest_port_from,
                      'dstport_or_icmpcode_last': dest_port_to})
        else:
            rules.append({'is_permit': int(permit == True),
                      'is_ipv6': 0,
                      'src_ip_addr': dest_ip_bytes,
                      'src_ip_prefix_len': dest_ip_prefix,
                      'dst_ip_addr': src_ip_bytes,
                      'dst_ip_prefix_len': src_ip_prefix,
                      'proto': p,
                      'srcport_or_icmptype_first': dest_port_from,
                      'srcport_or_icmptype_last': dest_port_to,
                      'dstport_or_icmpcode_first': src_port_from,
                      'dstport_or_icmpcode_last': src_port_to})
    return rules

def _generate_acl_params(source, destination, permit, is_ingress):

    acl_rules = []
    dest_matches = []
    source_matches = []
    any = {}

    if destination is not None:
        traffic_id = destination.get('trafficId')
        if traffic_id is None:
            traffic_tags = destination.get('trafficTags')
            if traffic_tags is None:
                custom_rule = destination.get('ipProtoPort')
                if isinstance(custom_rule, list):
                    dest_matches.extend(custom_rule)
                else:
                    dest_matches.append(custom_rule)
            else:
                category = traffic_tags.get('category')
                service_class = traffic_tags.get('serviceClass')
                importance = traffic_tags.get('importance')
                dest_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                    None, category, service_class, importance)
        else:
            dest_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                traffic_id, None, None, None)
    else:
        dest_matches.append(any)

    if source is not None:
        traffic_id = source.get('trafficId')
        if traffic_id is None:
            custom_rule = source.get('ipPort')
            source_matches.append(custom_rule)
        else:
            source_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                traffic_id, None, None, None)
    else:
        source_matches.append(any)

    for dest_match in dest_matches:
        for source_match in source_matches:
            rules = _build_vpp_acl_params(
                source_match, dest_match, permit, is_ingress)
            acl_rules.extend(rules)

    return acl_rules


def _generate_acl_rule(id, acl_rules):

    cmd = {}
    add_params = {
        'acl_index': ctypes.c_uint(-1).value,
        'count': len(acl_rules),
        'r': acl_rules,
        'tag': ''
    }

    cmd['cmd'] = {}
    cmd['cmd']['name'] = "acl_add_replace"
    cmd['cmd']['descr'] = "Add Firewall ACL"
    cmd['cmd']['params'] = add_params
    cmd['cmd']['cache_ret_val'] = ('acl_index', id)

    cmd['revert'] = {}
    cmd['revert']['name'] = "acl_del"
    cmd['revert']['descr'] = "Remove Firewall ACL"
    cmd['revert']['params'] = {
        'substs' : [
            {
                'val_by_key': id,
                'add_param': 'acl_index'
            }
        ]
    }

    return cmd


def add_acl_rule(id, source, destination, permit, is_ingress, add_last_deny_ace):
    """ Function that encapsulates call to generation of ACL command and its params

    :param id: String identifier representing the ACL
    :param source: json/dict message repersenting the source
    :param destination: json/dict message repersenting the destination
    :param action: json/dict message repersenting the action
    :param is_ingress: Boolean representing is ingress or not
    :return: Dict representing the command
    """
    cmd = {}

    acl_rules = _generate_acl_params(source, destination, permit, is_ingress)
    if not acl_rules:
        fwglobals.log.error('Generated ACL rule is empty.\
                Check traffic tags. Source: %s Destination: %s' % (source, destination))
        raise Exception('Firewall policy - ACL generation failed')
    else:
        # Allow list ACL use case - At end of allow list, add the deny
        # Append acl definition with a deny entry - Block all other sources
        if (add_last_deny_ace):
            acl_rules.extend(_generate_acl_params(None, destination, False, is_ingress))
        cmd = _generate_acl_rule(id, acl_rules)
    return cmd


def add_interface_attachment(sw_if_index, ingress_acl_ids, egress_acl_ids):
    """ Prepares command dict required to attach array of ingress and egress
    ACL identifiers to an interface

    :param sw_if_index: Integer identifier that represents an interface in VPP
    :param ingress_acl_ids: Array of ingress ACL identifiers
    :param egress_acl_ids: Array of egress ACL identifiers
    :return: Dict representing the command
    """
    cmd = {}
    acl_ids = []
    ingress_count = 0
    if ingress_acl_ids is not None:
        acl_ids.extend(ingress_acl_ids)
        ingress_count = len(ingress_acl_ids)
    if egress_acl_ids is not None:
        acl_ids.extend(egress_acl_ids)

    add_params = {
        'sw_if_index': sw_if_index,
        'count': len(acl_ids),
        'n_input': ingress_count
        # acls param shall be added during execution
    }

    cmd['cmd'] = {}
    cmd['cmd']['name'] = "acl_interface_set_acl_list"
    cmd['cmd']['descr'] = "Attach ACLs to interface"
    cmd['cmd']['params'] = add_params
    cmd['cmd']['params']['substs'] = [{
        'val_by_func': 'map_keys_to_acl_ids',
        'arg': acl_ids,
        'add_param': 'acls'
    } ]

    cmd['revert'] = {}
    cmd['revert']['name'] = "acl_interface_set_acl_list"
    cmd['revert']['descr'] = "Detach ACLs from interface"
    cmd['revert']['params'] = {
        'sw_if_index': sw_if_index,
        'count': 0,
        'n_input': 0,
        'acls': []
    }

    return cmd
