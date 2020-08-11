#! /usr/bin/python

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020  flexiWAN Ltd.
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


# This script has the following functionality
# -> systemctl stop flexiwan-router
# -> systemctl stop vpp
# -> systemctl stop frr
# -> unbinds network interfaces
# -> reverts netplan config files
# -> reverts VPP startup config file
# If argument '-s' was provided:
# -> clean router configuration database

import os
import sys

agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(agent_root_dir)
import fwglobals
import fwutils
import fwnetplan

def main():
    """Entry point.
    """
    print ("Shutting down flexiwan-router...")
    fwglobals.initialize()
    os.system('systemctl stop flexiwan-router')
    fwutils.stop_vpp()
    fwnetplan.restore_linux_netplan_files()
    if '-s' in sys.argv:
        fwutils.reset_router_config()
    print ("Done.")

if __name__ == '__main__':
    main()
