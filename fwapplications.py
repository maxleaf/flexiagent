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

class FwApps:
    """Applications class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        def tree(): return defaultdict(tree)
        self.apps_map = tree()

    def app_add(self, name, acl_id, id, category, subcategory, priority):
        """Add application.

        :param name: Application name.
        :param acl_id: ACL id.
        :param id: Application id.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.

        :returns: None.
        """
        self.apps_map[category][subcategory][priority][name] = \
            {"acl_id": acl_id,
             "id": id}

    def app_remove(self, name):
        """Remove application.

        :param name: Application name.

        :returns: None.
        """
        del self.apps[category][subcategory][priority][name]

    def acl_id_list_get(self, name, category, subcategory, priority):
        """Get ACL id.

        :param name: Application name.
        :param category: Application category.
        :param subcategory: Application subcategory.
        :param priority: Application priority.

        :returns: ACL id.
        """
        acl_id_list = []

        acl_id_list.append(self.apps_map[category][subcategory][priority][name]["acl_id"])

        return acl_id_list

def initialize():
    """Initialize a singleton.

    :returns: None.
    """
    global g
    g = FwApps()

def is_initialized():
    """Check if singleton is initialized.

    :returns: 'True' if singleton is initialized and 'False' otherwise.
    """
    return 'g' in globals()