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
import fwutils
import fwglobals

class FwPolicies:
    """Policies class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        self.policy_index = 0

    def _generate_id(self, ret):
        """Generate identifier.

        :param ret:         Initial id value.

        :returns: identifier.
        """
        ret += 1
        if ret == 2 ** 32:  # sad_id is u32 in VPP
            ret = 0
        return ret

    def _generate_policy_id(self):
        """Generate SA identifier.

        :returns: New SA identifier.
        """
        self.policy_index = self._generate_id(self.policy_index)
        return copy.deepcopy(self.policy_index)

    def _encode_paths(self, next_hop):
        br_paths = []

        label_stack = {'is_uniform': 0,
                       'label': 0,
                       'ttl': 0,
                       'exp': 0}

        label_stack_list = []
        for i in range(16):
            label_stack_list.append(label_stack)

        br_paths.append({'next_hop': next_hop,
                         'weight': 1,
                         'afi': 0,
                         'sw_if_index': 4294967295,
                         'preference': 0,
                         'table_id': 0,
                         'next_hop_id': 4294967295,
                         'is_udp_encap': 0,
                         'n_labels': 0,
                         'label_stack': label_stack_list})

        return br_paths

    def policy_add(self, id, app, category, subcategory, priority, pci, next_hop):
        """Add policy.

        :param id: Policy id.
        :param app: Application name.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.
        :param pci: PCI index.
        :param next_hop: Next hop ip address.

        :returns: None.
        """
        acl_id_list = fwglobals.g.apps_api.acl_id_list_get(app, category, subcategory, priority)
        sw_if_index = fwutils.pci_to_vpp_sw_if_index(pci)

        for acl_id in acl_id_list:
            policy_id = self._generate_policy_id()
            priority = 0
            is_ipv6 = 0

            #_add_policy(app, policy_id, acl_id, ip_bytes, cmd_list)
            #_attach_policy(sw_if_index, app, policy_id, priority, is_ipv6, cmd_list)

    def policy_remove(self, id, app, category, subcategory, priority, pci, next_hop):
        """Remove policy.

        :param id: Policy id.
        :param app: Application name.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.
        :param pci: PCI index.
        :param next_hop: Next hop ip address.

        :returns: None.
        """
