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

from sqlitedict import SqliteDict

from fwobject import FwObject

class FwPolicies(FwObject):
    """Policies class representation.
    This is a persistent storage of VPP policies identifiers that are used on
    tunnel add/remove to reattach policies to the loopback interfaces.
    """

    def __init__(self, db_file):
        """Constructor method.
        """
        self.db_filename = db_file
        self.policies = SqliteDict(db_file, 'policies', autocommit=True)

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
        self.policies.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        self.policies.clear()

    def add_policy(self, policy_id, priority):
        """Stores policy into database.

        :returns: None.
        """
        self.policies[policy_id] = priority

    def remove_policy(self, policy_id):
        """Removes policy from database.

        :returns: None.
        """
        del self.policies[policy_id]

    def policies_get(self):
        """Get policies dictionary.

        :returns: Dictionary.
        """
        return self.policies
