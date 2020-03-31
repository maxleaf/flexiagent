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
        self.app_2_acl = {}
        self.categories = {}
        self.subcategories = {}
        self.importances = {}

    def _add_app_db(self, name, acl_id, category, subcategory, importance):
        self.app_2_acl[name] = acl_id

        if category:
            if category not in self.categories:
                self.categories[category] = set()
            self.categories[category].add(acl_id)

        if subcategory:
            if subcategory not in self.subcategories:
                self.subcategories[subcategory] = set()
            self.subcategories[subcategory].add(acl_id)

        if importance:
            if importance not in self.importances:
                self.importances[importance] = set()
            self.importances[importance].add(acl_id)

    def _remove_app_db(self, name, category, subcategory, importance):
        acl_id = self.app_2_acl[name]
        del self.app_2_acl[name]

        if category:
            self.categories[category].remove(acl_id)

        if subcategory:
            self.subcategories[subcategory].remove(acl_id)

        if importance:
            self.importances[importance].remove(acl_id)

    def _get_acl_id(self, name):
        return self.app_2_acl[name]

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
        category = params.get('category', None)
        subcategory = params.get('subcategory', None)
        importance = params.get('importance', None)

        self._add_app_db(name, acl_id, category, subcategory, importance)
        fwglobals.g.router_api.refresh_policies()

        reply = {'ok': 1}
        return reply

    def _remove_app_info(self, params):
        """Remove application.

        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        name = params['app']
        acl_id = params['acl_index']
        category = params.get('category', None)
        subcategory = params.get('subcategory', None)
        importance = params.get('importance', None)

        fwglobals.g.policy_api.remove_policy(acl_id)
        self._remove_app_db(name, category, subcategory, importance)

        reply = {'ok': 1}
        return reply

    def acl_id_list_get(self, name, category, subcategory, importance):
        """Get ACL id.

        :param name: Application name.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param importance: Application importance.

        :returns: ACL ids list.
        """
        acl_ids = set()
        sets = []

        if name:
            acl_ids.add(self._get_acl_id(name))
        else:
            if category and category in self.categories:
                sets.append(self.categories[category])

            if subcategory and subcategory in self.subcategories:
                sets.append(self.subcategories[subcategory])

            if importance and importance in self.importances:
                sets.append(self.importances[importance])

        if sets:
            acl_ids = set.intersection(*sets)

        return list(acl_ids)
