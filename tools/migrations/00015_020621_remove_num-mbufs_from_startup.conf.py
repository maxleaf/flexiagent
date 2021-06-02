################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020 flexiWAN Ltd.
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

# On upgrade this migration script removes the 'dpdk.num-mbufs' parameter from
# /etc/vpp/startup.conf and /etc/vpp/startup.conf.baseline files,
# as starting of vpp 21.01 it is not supported anymore and it causes vpp to fail
# to bootup. This parameter was replaces by the 'buffers.buffers-per-numa'.
# On downgrade this script removes the 'buffers.buffers-per-numa'.

import os
import sys

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwutils

def migrate(prev_version=None, new_version=None, upgrade=True):
    try:
        print("* Migrating startup.conf buffers ...")
        prev_major_version = int(prev_version.split('-')[0].split('.')[0])
        new_major_version  = int(new_version.split('-')[0].split('.')[0])

        if upgrade == 'upgrade' and prev_major_version < 4 and new_major_version >= 4:
            fwutils.vpp_startup_conf_remove_param('/etc/vpp/startup.conf', 'dpdk.num-mbufs')
            fwutils.vpp_startup_conf_remove_param('/etc/vpp/startup.conf.baseline', 'dpdk.num-mbufs')

        if upgrade == 'downgrade' and prev_major_version >= 4 and new_major_version < 4:
            fwutils.vpp_startup_conf_remove_param('/etc/vpp/startup.conf', 'buffers.buffers-per-numa')
            fwutils.vpp_startup_conf_remove_param('/etc/vpp/startup.conf.baseline', 'buffers.buffers-per-numa')

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate("")

