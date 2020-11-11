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
import fwnetplan
import fwtranslate_revert
import fwutils
import fwtranslate_add_non_dpdk_interface
import fwtranslate_add_lte_interface
import fwtranslate_add_dpdk_interface

# add_interface
# --------------------------------------
# Translates request:
#
#    {
#      "message": "add-interface",
#      "params": {
#           "dev_id":"0000:00:08.00",
#           "addr":"10.0.0.4/24",
#           "routing":"ospf"
#      }
#    }
#
# into list of commands:
#
#    1.vpp.cfg
#    ------------------------------------------------------------
#    01. sudo vppctl set int state 0000:00:08.00 up
#    02. sudo vppctl set int ip address 0000:00:08.00 192.168.56.107/24
#
#    2.Netplan config
#    ------------------------------------------------------------
#    03. add interface section into configuration file
#
#    3. Add interface address to ospfd.conf for FRR
#    04. add 'network 192.168.56.107/24 area 0.0.0.0' line:
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#      network 192.168.56.107/24 area 0.0.0.0
#
#    07. sudo systemctl restart frr
#
def add_interface(params):
    """Generate commands to configure interface in Linux and VPP

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    dev_id  = params['dev_id']

    if fwutils.is_dpdk_interface(dev_id):
        cmd_list = fwtranslate_add_dpdk_interface.add(params)

    if fwutils.is_lte_interface(dev_id):
        cmd_list = fwtranslate_add_lte_interface.add(params)

    if fwutils.is_wifi_interface(dev_id):
        cmd_list = fwtranslate_add_non_dpdk_interface.add(params)

    return cmd_list

def modify_interface(new_params, old_params):
    """Generate commands to modify interface configuration in Linux and VPP

    :param new_params:  The new configuration received from flexiManage.
    :param old_params:  The current configuration of interface.

    :returns: List of commands.
    """
    cmd_list = []

    # For now we don't support real translation to command list.
    # We just return empty list if new parameters have no impact on Linux or
    # VPP, like PublicPort, and non-empty dummy list if parameters do have impact
    # and translation is needed. In last case the modification will be performed
    # by replacing modify-interface with pair of remove-interface & add-interface.
    # I am an optimistic person, so I believe that hack will be removed at some
    # point and real translation will be implemented.

    # Remove all not impacting parameters from both new and old parameters and
    # compare them. If they are same, no translation is needed.
    #
    not_impacting_params = [ 'PublicIP', 'PublicPort', 'useStun']
    copy_old_params = copy.deepcopy(old_params)
    copy_new_params = copy.deepcopy(new_params)

    for param in not_impacting_params:
        if param in copy_old_params:
            del copy_old_params[param]
        if param in copy_new_params:
            del copy_new_params[param]

    same = fwutils.compare_request_params(copy_new_params, copy_old_params)
    if not same:    # There are different impacting parameters
        cmd_list = [ 'stub' ]
    return cmd_list

def get_request_key(params):
    """Get add interface command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-interface:%s' % params['dev_id']
