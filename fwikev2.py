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


class FwIKEv2Tunnels:
    """FwIKEv2Tunnels class representation.
    This is a persistent storage of IKEv2 tunnels.
    """

    def __init__(self, db_file):
        """Constructor method.
        """
        self.db_filename = db_file
        self.db = SqliteDict(db_file, 'ikev2tunnels', autocommit=True)

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
        self.db.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        self.db.clear()

    def add_tunnel(self, src, bd_id, profile):
        """Stores tunnel into database.

        :returns: None.
        """
        self.db[src] = {'bridge_id': bd_id, 'profile': profile}

    def remove_tunnel(self, src):
        """Removes tunnel from database.

        :returns: None.
        """
        del self.db[src]

    def get_tunnel(self, src):
        """Get tunnel from database.

        :returns: Dictionary.
        """
        return self.db[src]

    def get_tunnels(self):
        """Get tunnels from database.

         :returns: Dictionary.
         """
        return self.db

