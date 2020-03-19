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

import ctypes
import os
import re
import time
import fwutils
from collections import defaultdict

import fwglobals

fwapps_api = {
    'add-app-info':         '_add_app_info',
    'remove-app-info':      '_remove_app_info',
}

class FwApps:
    """Applications class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        def tree(): return defaultdict(tree)
        self.apps_map = tree()

    def _create_rule(self, is_ipv6=0, is_permit=0, proto=0,
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

    def _add_acl(self, params, cmd_list):
        """Generate ACL command.

         :param params:        Parameters from flexiManage.
         :param cmd_list:      Commands list.

         :returns: None.
         """
        # acl.api.json: acl_add_replace (..., tunnel <type vl_api_acl_rule_t>, ...)
        rules = []

        for rule in params['rules']:
            ip_bytes, ip_len = fwutils.ip_str_to_bytes(rule['ip'])

            rules.append(self._create_rule(is_ipv6=0, is_permit=1,
                                           dport_from=rule['port-range-low'],
                                           dport_to=rule['port-range-high'],
                                           d_prefix=rule['ip-prefix'],
                                           proto=rule['proto'],
                                           d_ip=ip_bytes))

        cmd_params = {
            'acl_index': ctypes.c_uint(-1).value,
            'count': len(rules),
            'r': rules,
            'tag': ''
        }

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "acl_add_replace"
        cmd['cmd']['params'] = cmd_params
        cmd['cmd']['descr'] = "Add ACL for app %s" % (params['app'])
        cmd_list.append(cmd)

    def _remove_acl(self, acl_index, cmd_list):
        """Generate delete ACL command.

         :param acl_index:     ACL index.
         :param cmd_list:      Commands list.

         :returns: None.
         """
        # acl.api.json: acl_del (..., acl_index, ...)

        cmd_params = {
            'acl_index': acl_index
        }

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name'] = "acl_del"
        cmd['cmd']['params'] = cmd_params
        cmd_list.append(cmd)

    def call(self, req, params):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        handler = fwapps_api.get(req)
        assert handler, 'fwapps_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwapps_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwapps_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _add_app_info(self, params):
        """Add application.

        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        name = params['app']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']

        cmd_list = []
        cmd_cache = {}
        self._add_acl(params, cmd_list)
        for cmd in cmd_list:
            result = {'result_attr': 'acl_index', 'cache': cmd_cache, 'key': 'acl_index'}
            fwglobals.g.handle_request(cmd['cmd']['name'], cmd['cmd']['params'], result)
            acl_id = cmd_cache['acl_index']
            self.apps_map[category][subcategory][priority][name] = {'acl_id': acl_id}

        fwglobals.g.policy_api.refresh_policies()

        reply = {'ok': 1}
        return reply

    def _remove_app_info(self, params):
        """Remove application.

        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        name = params['app']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']
        acl_id = self.apps_map[category][subcategory][priority][name]['acl_id']
        cmd_list = []

        fwglobals.g.policy_api.remove_policy(acl_id)

        self._remove_acl(acl_id, cmd_list)
        for cmd in cmd_list:
            fwglobals.g.handle_request(cmd['cmd']['name'], cmd['cmd']['params'])
            del self.apps_map[category][subcategory][priority][name]

        reply = {'ok': 1}
        return reply

    def _priority_iterate(self, category, subcategory, priority, acl_id_list):
        """Get ACL id.

        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.
        :param acl_id_list: ACL id list.

        :returns: None.
        """
        for app in self.apps_map[category][subcategory][priority].values():
            acl_id_list.append(app['acl_id'])

    def _subcategory_iterate(self, category, subcategory, acl_id_list):
        """Get ACL id.

        :param category: Application category.
        :param subcategory: Application subcategory.
        :param acl_id_list: ACL id list.

        :returns: None.
        """
        for priority in self.apps_map[category][subcategory].keys():
            self._priority_iterate(category, subcategory, priority, acl_id_list)

    def _category_iterate(self, category, acl_id_list):
        """Get ACL id.

        :param category: Application category.
        :param acl_id_list: ACL id list.

        :returns: None.
        """
        for subcategory in self.apps_map[category].keys():
            self._subcategory_iterate(category, subcategory, acl_id_list)

    def acl_id_list_get(self, name, category, subcategory, priority):
        """Get ACL id.

        :param name: Application name.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.

        :returns: ACL id.
        """
        acl_id_list = []

        if not name:
            if priority < 0:
                if not subcategory:
                    self._category_iterate(category, acl_id_list)
                else:
                    self._subcategory_iterate(category, subcategory, acl_id_list)
            else:
                self._priority_iterate(category, subcategory, priority, acl_id_list)
        else:
            acl_id_list.append(self.apps_map[category]
                               [subcategory][priority][name]['acl_id'])

        return acl_id_list
