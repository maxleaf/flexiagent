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
import time
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
        acl_id = params['acl_index']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']

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
        acl_id = params['acl_index']
        category = params['category']
        subcategory = params['subcategory']
        priority = params['priority']

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