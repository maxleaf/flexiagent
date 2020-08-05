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
#
# Device database migration:
# --------------------------
# Migration is called on upgrade or downgrade to/from this release.
# 1) Upgrade is called after this version is installed and before restarting the daemon service
# 2) Downgrade is called before this version is uninstalled
# 3) Every migration script will get <from_version>, <to_version> and 'upgrade'/'downgrade' parameters
#
# The migration script should decide based on the versions how to upgrade or downgrade to/from this release.
#
# Guidelines:
# * If the migrate is backward compatible, run it only on any upgrade to this release and don't run on downgrade
# * Use as much as possible major releases, for example if version 1.2.14 is released, then 1.3.10 is released.
# The migration script in 1.3.10 should run migrations from 1.2.X to 1.3.10 (and not from 1.2.14).
# This allows version 1.2.15 developed after 1.3.10, to upgrade as well.
# * For specific release cases/bugs use the exact version.

import os
import sys
import glob

FW_EXIT_CODE_OK      = 0
FW_EXIT_CODE_ERROR   = 0x1

def run_migrations(prev_version, new_version, upgrade):
    print("Post installation Migrations from %s to %s on %s" % (prev_version, new_version, upgrade))
    # Get files path for migration
    migration_path = os.path.abspath(os.path.dirname(__file__) + './../migrations')
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
        imported.migrate(prev_version, new_version, upgrade)

if __name__ == '__main__':
    try:
        if len(sys.argv) < 4:
            print("Usage: %s <prev_version> <new_version> <upgrade|downgrade>" % sys.argv[0])
            exit(FW_EXIT_CODE_ERROR)

        # Parse version numbers. For example 1.3.9-205.abcdef will be converted to 1.3.9
        prev_version = sys.argv[1].split('-')[0]
        new_version = sys.argv[2].split('-')[0]
        upgrade = sys.argv[3]

        run_migrations(prev_version, new_version, upgrade)
    except Exception as e:
        print("Post install error: %s" % (str(e)))
    exit(FW_EXIT_CODE_OK)
