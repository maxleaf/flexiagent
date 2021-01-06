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

import getopt
import os
import sys
import shutil

agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(agent_root_dir)
import fwglobals
import fwutils
import fwnetplan

def parse_argv(argv):
    options = [
        'quiet',        # If True no prints onto screen will be done
        'clean_cfg'     # If True the router configuration database will be reset
    ]
    arg_quiet     = False
    arg_clean_cfg = False

    opts,_ = getopt.getopt(argv, '', options)
    for opt, _ in opts:
        if opt == '--quiet':
            arg_quiet = True
        elif opt == '--clean_cfg':
            arg_clean_cfg = True
    return (arg_quiet, arg_clean_cfg)

def main():
    """Entry point.
    """

    (arg_quiet, arg_clean_cfg) = parse_argv(sys.argv[1:])

    if not arg_quiet:
        print ("Shutting down flexiwan-router...")
    fwglobals.initialize()
    os.system('systemctl stop flexiwan-router')
    fwutils.stop_vpp()
    fwnetplan.restore_linux_netplan_files()

    # reset startup.conf file
    if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_BACKUP, fwglobals.g.VPP_CONFIG_FILE)
    if arg_clean_cfg:
        fwutils.reset_router_config()
        fwutils.reset_fw_linux_config()

    if not arg_quiet:
        print ("Done")

if __name__ == '__main__':

    if not fwutils.check_root_access():
        sys.exit(1)

    main()
