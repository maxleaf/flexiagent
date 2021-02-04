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
import fw_acl_command_helpers
import fw_nat_command_helpers

class INBOUND_NAT_TYPE:
    NAT_1TO1 = 1
    PORT_FORWARD = 2
    IDENTITY_MAPPING = 3

DEFAULT_ALLOW_ID = 'fw_default_allow_id'


def _convert_dest_to_acl_rule_params(destination):

    dest_rule_params = {}
    rule_array = []

    ports = destination['ports']
    protocols = destination.get('protocols')
    for proto in protocols:
        rule_array.append({
            'ports': ports,
            'protocol': proto
        })
    dest_rule_params['ipProtoPort'] = rule_array
    return dest_rule_params


def _process_inbound_rules(inbound_rules, rule_type):

    intf_attachments = {}
    cmd_list = []
    for rule in inbound_rules['rules']:

        classification = rule.get('classification')
        source = classification.get('source')
        action = rule.get('action')

        destination = classification.get('destination')
        if rule_type != INBOUND_NAT_TYPE.NAT_1TO1:
            ingress_id = 'fw_wan_ingress__type_%d_rule_%s' % (
                rule_type, rule['id'])
            dest_rule_params = _convert_dest_to_acl_rule_params(destination)
            cmd_list.append(fw_acl_command_helpers.add_acl_rule(
                ingress_id, source, dest_rule_params, True, True, True))

        if rule_type == INBOUND_NAT_TYPE.IDENTITY_MAPPING:
            dev_id_params = destination.get('interfaces', [])
            if not dev_id_params:
                interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
                for intf in interfaces:
                    dev_id_params.append(intf['dev_id'])
        else:
            dev_id_params = [destination['interface']]

        for dev_id in dev_id_params:
            if intf_attachments.get(dev_id) is None:
                intf_attachments[dev_id] = {}
                intf_attachments[dev_id]['ingress'] = []
            if rule_type != INBOUND_NAT_TYPE.NAT_1TO1:
                intf_attachments[dev_id]['ingress'].append(ingress_id)

    for dev_id, value in intf_attachments.items():
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id, None)
        if sw_if_index is None:
            fwglobals.log.error('Firewall policy - LAN dev_id not found: ' + dev_id +
                                ' ' + str(value['ingress']))
            raise Exception('Firewall policy - inbound : dev_id not resolved')

        if value['ingress']:
            # Add last default ACL as allow ALL
            value['ingress'].append(DEFAULT_ALLOW_ID)
            fwglobals.log.info('Firewall policy - WAN dev_id: ' +
                               dev_id + ' ' + str(value['ingress']))
            cmd_list.append(fw_acl_command_helpers.add_interface_attachment(
                sw_if_index, value['ingress'], None))

        if rule_type == INBOUND_NAT_TYPE.NAT_1TO1:
            cmd_list.extend(fw_nat_command_helpers.get_nat_1to1_config(
                sw_if_index, action['internalIP']))
        elif rule_type == INBOUND_NAT_TYPE.PORT_FORWARD:
            cmd_list.extend(fw_nat_command_helpers.get_nat_port_forward_config(
                sw_if_index, destination['protocols'], destination['ports'], action['internalIP'],
                action['internalPortStart']))
        elif rule_type == INBOUND_NAT_TYPE.IDENTITY_MAPPING:
            cmd_list.extend(fw_nat_command_helpers.get_nat_identity_config(
                sw_if_index, destination['protocols'], destination['ports']))
        else:
            raise Exception("Invalid Inbound NAT type %d" % rule_type)

    return cmd_list


# Outbound firewall rule - Sample representation
# {
#     "entity": "agent",
#     "message": "remove-firewall-policy",
#     "params": {
#         "outbound": {
#             "rules": [
#                 {
#                     "id": "1",
#                     "classification": {
#                         "destination": {
#                             "ipProtoPort": {
#                                 "ip": "172.16.0.0/16",
#                                 "protocol": "tcp",
#                                 "ports": "622-699"
#                             }
#                         },
#                         "source": {
#                             "ipPort": {
#                                 "ports": "5555"
#                             }
#                         }
#                     },
#                     "action": {
#                         "permit": true,
#                         "interfaces": ["pci:0000:00:03.00"]
#                         }
#                     }
#                 }
#             ]
#         }
#     }
# }

def _process_outbound_rules(outbound_rules):
    """Processes outbound firewall rules and generates corresponding commands
    - Performs generation of ACL based on source and destination match conditions
    - ACLs are generated to represent both direction of LAN (ingress and egress)
    - Attaches the generated ACLs on both the ingress and egress of specified LAN interfaces

    :param outbound_rules: json/dict message carrying outbound rules
    :return: Array of commands and each command is a dict
    """
    intf_attachments = {}
    cmd_list = []
    for rule in outbound_rules['rules']:

        classification = rule.get('classification')
        if classification is not None:
            destination = classification.get('destination')
            source = classification.get('source')
        else:
            destination = None
            source = None
        action = rule['action']
        permit = action['permit']
        ingress_id = 'fw_lan_ingress_rule_%s' % rule['id']
        cmd_list.append(fw_acl_command_helpers.add_acl_rule(
            ingress_id, source, destination, permit, True, False))
        egress_id = 'fw_lan_egress_rule_%s' % rule['id']
        cmd_list.append(fw_acl_command_helpers.add_acl_rule(
            egress_id, source, destination, permit, False, False))

        # interfaces ['Array of LAN device ids]
        dev_id_params = action.get('interfaces', [])
        if not dev_id_params:
            interfaces = fwglobals.g.router_cfg.get_interfaces(type='lan')
            for intf in interfaces:
                dev_id_params.append(intf['dev_id'])

        for dev_id in dev_id_params:
            if intf_attachments.get(dev_id) is None:
                intf_attachments[dev_id] = {}
                intf_attachments[dev_id]['ingress'] = []
                intf_attachments[dev_id]['egress'] = []
            intf_attachments[dev_id]['ingress'].append(ingress_id)
            intf_attachments[dev_id]['egress'].append(egress_id)

    for dev_id, value in intf_attachments.items():
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id, None)
        if sw_if_index is None:
            fwglobals.log.error('Firewall policy - LAN dev_id not found: ' + dev_id +
                                ' ' + str(value['ingress']) + ' ' + str(value['egress']))
            raise Exception('Firewall policy - outbound : dev_id not resolved')

        # Add last default ACL as allow ALL
        value['ingress'].append(DEFAULT_ALLOW_ID)
        value['egress'].append(DEFAULT_ALLOW_ID)

        cmd_list.append(fw_acl_command_helpers.add_interface_attachment(
            sw_if_index, value['ingress'], value['egress']))

    return cmd_list


def add_firewall_policy(params):
    """Processes the firewall rules and generates corresponding commands
    Types of firewall rules
        1. Outbound rules - Attached on LAN interfaces
        2. Inbound rules - Attach on WAN ingress and create NAT mappings
        for 1:1 NAT, Port forward and Edge Access

    :param params: json/dict carrying the firewall message
    :return: Array of commands and each command is a dict
    """
    cmd_list = []
    # Add default Allow all ACLs
    # Traffic with no static/identity mapping shall get dropped by NAT lookup failure
    cmd_list.append(fw_acl_command_helpers.add_acl_rule(DEFAULT_ALLOW_ID,
                                                        None, None, True, True, False))

    outbound_rules = params.get('outbound')
    if (outbound_rules is not None):
        cmd_list.extend(_process_outbound_rules(outbound_rules))

    inbound_rules = params.get('inbound')
    if (inbound_rules is not None):
        nat_1to1_rules = inbound_rules.get("NAT_1to1")
        if (nat_1to1_rules is not None):
            cmd_list.extend(_process_inbound_rules(
                nat_1to1_rules, INBOUND_NAT_TYPE.NAT_1TO1))
        port_forward_rules = inbound_rules.get("Port_Forward")
        if (port_forward_rules is not None):
            cmd_list.extend(_process_inbound_rules(
                port_forward_rules, INBOUND_NAT_TYPE.PORT_FORWARD))
        edge_access_rules = inbound_rules.get("Edge_Access")
        if (edge_access_rules is not None):
            cmd_list.extend(_process_inbound_rules(
                edge_access_rules, INBOUND_NAT_TYPE.IDENTITY_MAPPING))

    return cmd_list


def get_request_key(params):
    """Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-firewall-policy'
