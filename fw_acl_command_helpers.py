"""
Helper functions to convert classifications and actions into VPP ACL commands
"""

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

import ctypes

import fwglobals
import fwutils


def add_acl_rule(acl_id, source, destination, permit, is_ingress, add_last_deny_ace):
    """ Function that encapsulates call to generation of ACL command and its params

    :param id: String identifier representing the ACL
    :param source: json/dict message repersenting the source
    :param destination: json/dict message repersenting the destination
    :param action: json/dict message repersenting the action
    :param is_ingress: Boolean representing is ingress or not
    :return: Dict representing the command
    """

    def convert_match_to_acl_param(rule):

        ip_with_prefix = rule.get('ip')
        if not ip_with_prefix:
            ip_with_prefix = "0.0.0.0/0"

        ports = rule.get('ports')
        if ports:
            port_from, port_to = fwutils.ports_str_to_range(ports)
        else:
            port_from = 0
            port_to = 0xffff
        protocols = rule.get('protocols')
        if protocols is None:
            protocol_single = rule.get('protocol')
            if protocol_single:
                protocols = [protocol_single]
        protocols_map = []
        if protocols:
            for protocol in protocols:
                protocols_map.append(fwutils.proto_map[protocol])
        elif ports:
            protocols_map.append(fwutils.proto_map['tcp'])
            protocols_map.append(fwutils.proto_map['udp'])

        return ip_with_prefix, port_from, port_to, protocols_map if protocols_map else None


    def build_vpp_acl_params(source_match, dest_match, permit, is_ingress):

        rules = []
        src_ip_with_prefix, src_port_from, src_port_to, src_proto =\
            convert_match_to_acl_param(source_match)
        dst_ip_with_prefix, dest_port_from, dest_port_to, dst_proto =\
            convert_match_to_acl_param(dest_match)
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

        for proto in dst_proto:
            if proto == fwutils.proto_map['icmp']:
                sport_from = sport_to = dport_from = dport_to = 0
            else:
                sport_from = src_port_from
                sport_to = src_port_to
                dport_from = dest_port_from
                dport_to = dest_port_to

            if is_ingress:
                rules.append({'is_permit': int(permit is True),
                              'is_ipv6': 0,
                              'src_prefix': src_ip_with_prefix,
                              'dst_prefix': dst_ip_with_prefix,
                              'proto': proto,
                              'srcport_or_icmptype_first': sport_from,
                              'srcport_or_icmptype_last': sport_to,
                              'dstport_or_icmpcode_first': dport_from,
                              'dstport_or_icmpcode_last': dport_to})
            else:
                rules.append({'is_permit': int(permit is True),
                              'is_ipv6': 0,
                              'src_prefix': dst_ip_with_prefix,
                              'dst_prefix': src_ip_with_prefix,
                              'proto': proto,
                              'srcport_or_icmptype_first': dport_from,
                              'srcport_or_icmptype_last': dport_to,
                              'dstport_or_icmpcode_first': sport_from,
                              'dstport_or_icmpcode_last': sport_to})
        return rules


    def is_match_unique(match1, match2):

        if match1 and match2:
            ip_with_prefix1, port_from1, port_to1, _ =\
                convert_match_to_acl_param(match1)
            ip_with_prefix2, port_from2, port_to2, _ =\
                convert_match_to_acl_param(match2)
            if ((ip_with_prefix1 == ip_with_prefix2) and (port_from1 == port_from2) and
                    (port_to1 == port_to2)):
                return 0
        return 1


    def generate_acl_params(source, destination, permit, is_ingress):

        acl_rules = []
        dest_matches = []
        source_matches = []
        any_match = {}

        if destination:
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
            dest_matches.append(any_match)

        if source:
            traffic_id = source.get('trafficId')
            if traffic_id is None:
                custom_rule = source.get('ipPort')
                source_matches.append(custom_rule)
            else:
                source_matches = fwglobals.g.traffic_identifications.get_traffic_rules(
                    traffic_id, None, None, None)
        else:
            source_matches.append(any_match)

        for dest_match in dest_matches:
            source_match_prev = None
            for source_match in source_matches:
                if is_match_unique(source_match, source_match_prev):
                    rules = build_vpp_acl_params(
                        source_match, dest_match, permit, is_ingress)
                    acl_rules.extend(rules)
                    source_match_prev = source_match

        return acl_rules


    def generate_acl_rule(acl_id, acl_rules):

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
        cmd['cmd']['cache_ret_val'] = ('acl_index', acl_id)

        cmd['revert'] = {}
        cmd['revert']['name'] = "acl_del"
        cmd['revert']['descr'] = "Remove Firewall ACL"
        cmd['revert']['params'] = {
            'substs': [
                {
                    'val_by_key': acl_id,
                    'add_param': 'acl_index'
                }
            ]
        }

        return cmd

    cmd = {}

    acl_rules = generate_acl_params(source, destination, permit, is_ingress)
    if not acl_rules:
        fwglobals.log.error('Generated ACL rule is empty.\
                Check traffic tags. Source: %s Destination: %s' % (source, destination))
        raise Exception('Firewall policy - ACL generation failed')
    else:
        # Allow list ACL use case - At end of allow list, add the deny
        # Append acl definition with a deny entry - Block all other sources
        if add_last_deny_ace:
            acl_rules.extend(generate_acl_params(
                None, destination, False, is_ingress))
        cmd = generate_acl_rule(acl_id, acl_rules)
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
    if ingress_acl_ids:
        acl_ids.extend(ingress_acl_ids)
        ingress_count = len(ingress_acl_ids)
    if egress_acl_ids:
        acl_ids.extend(egress_acl_ids)

    add_params = {
        'sw_if_index': sw_if_index,
        'count': len(acl_ids),
        'n_input': ingress_count
    }

    cmd['cmd'] = {}
    cmd['cmd']['name'] = "acl_interface_set_acl_list"
    cmd['cmd']['descr'] = "Attach ACLs to interface"
    cmd['cmd']['params'] = add_params
    cmd['cmd']['params']['substs'] = [{
        'val_by_func': 'map_keys_to_acl_ids',
        'func_uses_cmd_cache': True,
        'arg': {'keys': acl_ids},
        'add_param': 'acls'
    }]

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
