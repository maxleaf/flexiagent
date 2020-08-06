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

# This migration script fix the dhcp stop made by mistake on release 1.3.9

import os
import re
import yaml
import sys
import subprocess

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwglobals
import fwdb_requests
import fwutils

from fwdb_requests import FwDbRequests

SQLITE_DB_FILE = '/etc/flexiwan/agent/.requests.sqlite'


def _is_start_router_in_db():
    with FwDbRequests(SQLITE_DB_FILE) as db_requests:
        for key, request in db_requests.db.items():
            if re.match('start-router', key):
                return True
    return False


def migrate(prev_version, new_version, upgrade):
    if upgrade != 'upgrade' or prev_version.split('-')[0] != '1.3.9':
        return
    try:
        print("* Migrating start-router...")
        if not _is_start_router_in_db():
            with FwDbRequests(SQLITE_DB_FILE) as db_requests:
                db_requests.update('start-router', {}, {}, [], False)

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()


