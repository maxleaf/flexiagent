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

fwpolicy_api = {
    'add-policy-info':         '_add_policy_info',
    'remove-policy-info':      '_remove_policy_info',
}

class FwPolicies:
    """Policies class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        self.policy_index = 0

    def call(self, req, params):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        handler = fwpolicy_api.get(req)
        assert handler, 'fwpolicy_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwpolicy_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwpolicy_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

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

    def _add_policy(self, app, policy_id, acl_id, ip, cmd_list):
        """Generate add policy command.

         :param app:        Application name.
         :param policy_id:  Policy id.
         :param acl_id:     ACL id.
         :param ip:         Ip address.
         :param cmd_list:   Commands list.

         :returns: List of commands.
         """
        paths = self._encode_paths(ip)

        rule = ({'policy_id': policy_id,
                 'acl_index': acl_id,
                 'paths': paths,
                 'n_paths': len(paths)})

        cmd_params = {
            'is_add': 1,
            'policy': rule
        }

        # abf.api.json: abf_policy_add_del (is_add, ..., <type vl_api_abf_policy_t>, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "abf_policy_add_del"
        cmd['cmd']['params'] = cmd_params
        cmd['cmd']['descr'] = "Add ABF for app %s" % (app)
        cmd['revert'] = {}
        cmd['revert']['name'] = 'abf_policy_add_del'
        cmd['revert']['params'] = copy.deepcopy(cmd_params)
        cmd['revert']['params']['is_add'] = 0
        cmd['revert']['descr'] = "Delete ABF for app %s" % (app)
        cmd_list.append(cmd)

        return cmd_list

    def _attach_policy(self, sw_if_index, app, policy_id, priority, is_ipv6, cmd_list):
        """Generate add policy command.

         :param sw_if_index: Interface index.
         :param app:         Application name.
         :param policy_id:   Policy id.
         :param priority:    Priority.
         :param is_ipv6:     IPv6 flag.
         :param cmd_list:    Commands list.

         :returns: List of commands.
        """
        attach = ({'policy_id': policy_id,
                   'sw_if_index': sw_if_index,
                   'priority': priority,
                   'is_ipv6': is_ipv6})

        cmd_params = {
            'is_add': 1,
            'attach': attach
        }

        # abf.api.json: abf_itf_attach_add_del (is_add, ..., <type vl_api_abf_itf_attach_t>, ...)
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "abf_itf_attach_add_del"
        cmd['cmd']['params'] = cmd_params
        cmd['cmd']['descr'] = "Attach ABF for app %s" % (app)
        cmd['revert'] = {}
        cmd['revert']['name'] = 'abf_itf_attach_add_del'
        cmd['revert']['params'] = copy.deepcopy(cmd_params)
        cmd['revert']['params']['is_add'] = 0
        cmd['revert']['descr'] = "Attach ABF for app %s" % (app)
        cmd_list.append(cmd)

    def _translate(self, app, category, subcategory, priority, pci, next_hop, cmd_list):
        acl_id_list = fwglobals.g.apps_api.acl_id_list_get(app, category, subcategory, priority)
        sw_if_index = fwutils.pci_to_vpp_sw_if_index(pci)
        priority = 0
        is_ipv6 = 0

        for acl_id in acl_id_list:
            policy_id = self._generate_policy_id()

            self._add_policy(app, policy_id, acl_id, next_hop, cmd_list)
            self._attach_policy(sw_if_index, app, policy_id, priority, is_ipv6, cmd_list)

    def _add_policy_info(self, params):
        """Save policy information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        app = params['app']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']
        pci = params['pci']
        next_hop = params['next_hop']
        cmd_list = []

        self._translate(app, category, subcategory, priority, pci, next_hop, cmd_list)

        fwglobals.g.router_api._execute('add-policy', 'add-policy:' + str(id), cmd_list)

        reply = {'ok': 1}
        return reply

    def _remove_policy_info(self, params):
        """Remove policy information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        app = params['app']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']
        pci = params['pci']
        next_hop = params['next_hop']
        cmd_list = []

        self._translate(app, category, subcategory, priority, pci, next_hop, cmd_list)

        fwglobals.g.router_api._revert(cmd_list)

        reply = {'ok': 1}
        return reply
