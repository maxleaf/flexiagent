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

# This script run post install tasks:
#  - device database migrations

import os
import sys
import glob

FW_EXIT_CODE_OK = 0

def run_migrations():
    print("Post installation Migrations...")
    # Get files path for migration
    migration_path = os.path.abspath(os.path.dirname(__file__) + '/../migrations')
    # Add path to system to allow imports
    sys.path.append(migration_path)
    # Get all python files in the migration path
    migration_files = glob.glob(migration_path + '/*.py' )
    # Sort by file name
    migration_files = sorted(migration_files)
    for file in migration_files:
        # Get the file name
        imported_file = os.path.split(file)[1]
        # Remove the .py
        imported_file = os.path.splitext(imported_file)[0]
        print("Migrating file %s" % (imported_file))
        imported = __import__(imported_file)
        imported.up()

if __name__ == '__main__':
    try:
        run_migrations()
    except Exception as e:
        print("Post install error: %s" % (str(e)))
    exit(FW_EXIT_CODE_OK)
