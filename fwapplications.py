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

import fwglobals

class FwApps:
    """Applications class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        self.apps_map = {}

    def app_add(self, name, acl_id):
        self.apps_map[name] = acl_id

    def acl_id_get(self, name):
        return self.apps_map[name]

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