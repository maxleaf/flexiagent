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
import fwglobals
import fwutils
import json
import os
import re
from sqlitedict import SqliteDict
import time


fwapps_api = {
    'add-app-info':         '_add_app_info',
    'remove-app-info':      '_remove_app_info',
}

class FwApps:
    """Applications class representation.
    """

    def __init__(self, db_file):
        """Constructor method.
        """
        self.db_filename = db_file
        self.app_2_acl = SqliteDict(db_file, 'app_2_acl', autocommit=True)
        self.categories = SqliteDict(db_file, 'categories', autocommit=True)
        self.subcategories = SqliteDict(db_file, 'subcategories', autocommit=True)
        self.importances = SqliteDict(db_file, 'importances', autocommit=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        self.app_2_acl.close()
        self.categories.close()
        self.subcategories.close()
        self.importances.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        self.app_2_acl.clear()
        self.categories.clear()
        self.subcategories.clear()
        self.importances.clear()

    def _add_acl_id(self, dict, key, acl_id):
        if key not in dict:
            dict[key] = '{}'

        json_dict = json.loads(dict[key])
        json_dict[acl_id] = acl_id
        dict[key] = json.dumps(json_dict)

    def _remove_acl_id(self, dict, key, acl_id):
        json_dict = json.loads(dict[key])
        del json_dict[acl_id]
        dict[key] = json.dumps(json_dict)

    def _get_acl_ids(self, dict, key):
        return set(json.loads(dict[key]).values())

    def _add_app_db(self, name, acl_id, category, serviceClass, importance):
        self.app_2_acl[name] = acl_id

        if category:
            self._add_acl_id(self.categories, category, acl_id)

        if serviceClass:
            self._add_acl_id(self.subcategories, serviceClass, acl_id)

        if importance:
            self._add_acl_id(self.importances, importance, acl_id)

    def _remove_app_db(self, name, category, serviceClass, importance):
        acl_id = self.app_2_acl[name]
        del self.app_2_acl[name]

        if category:
            self._remove_acl_id(self.categories, category, acl_id)

        if serviceClass:
            self._remove_acl_id(self.subcategories, serviceClass, acl_id)

        if importance:
            self._remove_acl_id(self.importances, importance, acl_id)

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
        name = params['name']
        acl_id = params['acl_index']
        category = params.get('category', None)
        serviceClass = params.get('serviceClass', None)
        importance = params.get('importance', None)

        self._add_app_db(name, acl_id, category, serviceClass, importance)
        fwglobals.g.router_api.refresh_policies()

        reply = {'ok': 1}
        return reply

    def _remove_app_info(self, params):
        """Remove application.

        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        name = params['name']
        acl_id = params['acl_index']
        category = params.get('category', None)
        serviceClass = params.get('serviceClass', None)
        importance = params.get('importance', None)

        fwglobals.g.policy_api.remove_policy(acl_id)
        self._remove_app_db(name, category, serviceClass, importance)

        reply = {'ok': 1}
        return reply

    def acl_id_list_get(self, name, category, serviceClass, importance):
        """Get ACL id.

        :param name: Application name.
        :param category: Application category.
        :param serviceClass: Application serviceClass.
        :param importance: Application importance.

        :returns: ACL ids list.
        """
        acl_ids = set()
        sets = []

        if name:
            acl_ids.add(self._get_acl_id(name))
        else:
            if category and category in self.categories:
                sets.append(self._get_acl_ids(self.categories, category))

            if serviceClass and serviceClass in self.subcategories:
                sets.append(self._get_acl_ids(self.subcategories, serviceClass))

            if importance and importance in self.importances:
                sets.append(self._get_acl_ids(self.importances, importance))

        if sets:
            acl_ids = set.intersection(*sets)

        return list(acl_ids)
