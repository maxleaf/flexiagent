#! /usr/bin/python3

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

    def dumps(self):
        """Prints content of database into string
        """

        app_2_acl = sorted(self.app_2_acl.keys())
        categories = sorted(self.categories.keys())
        subcategories = sorted(self.subcategories.keys())
        importances = sorted(self.importances.keys())

        db = {
            'app_2_acl': [ { key: self.app_2_acl[key] } for key in app_2_acl ],
            'categories': [ { key: self.categories[key] } for key in categories ],
            'subcategories': [ { key: self.subcategories[key] } for key in subcategories ],
            'importances': [ { key: self.importances[key] } for key in importances ],
        }

        return json.dumps(db, indent=2, sort_keys=True)

    def _add_acl_id(self, dict, key, acl_id):
        if key not in dict:
            dict[key] = '{}'

        json_dict = json.loads(dict[key])
        json_dict[acl_id] = acl_id
        dict[key] = json.dumps(json_dict)

    def _remove_acl_id(self, dict, key, acl_id):
        json_dict = json.loads(dict[key])
        del json_dict[str(acl_id)]
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

    def _remove_app_db(self, name, acl_id, category, serviceClass, importance):
        del self.app_2_acl[name]

        if category:
            self._remove_acl_id(self.categories, category, acl_id)

        if serviceClass:
            self._remove_acl_id(self.subcategories, serviceClass, acl_id)

        if importance:
            self._remove_acl_id(self.importances, importance, acl_id)

    def _get_acl_id(self, name):
        return self.app_2_acl[name]

    def add_remove_application(self, add, id, acl_index=None, category=None, serviceClass=None, importance=None):
        """Stores/removes application into/from database.

        :returns: Reply.
        """
        if add:
            self._add_app_db(id, acl_index, category, serviceClass, importance)
        else:
            self._remove_app_db(id, acl_index, category, serviceClass, importance)

    def acl_ids_get(self, name, category, serviceClass, importance):
        """Get ACL id.

        :param name: Application name.
        :param category: Application category.
        :param serviceClass: Application serviceClass.
        :param importance: Application importance.

        :returns: ACL ids set.
        """
        acl_ids = set()
        sets = []

        if name:
            if name in self.app_2_acl:
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

        return acl_ids
