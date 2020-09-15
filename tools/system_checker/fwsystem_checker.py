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


# This script checks if system is capable to run FlexiWAN Edge device.
# It adjusts various system parameters, if approved by user.
# This script should be run by the flexiwan-router installer
# as the last step of installation and before flexiwan-router.service is up.
# If it returns failure, the flexiwan-router.service should not be started.
# The script exits with:
#   0 on success
#   1 on unmet hard requirements
#   2 on unmet soft requirements
#   3 on system configuration failure
#   4 on on user aborted configuration

import os
import subprocess

import getopt
import importlib
import platform
import sys
import shutil

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwglobals
import fwutils

FW_EXIT_CODE_OK = 0
FW_EXIT_CODE_ERROR_UNMET_HARDWARE_REQUIREMENTS        = 0x1
FW_EXIT_CODE_ERROR_UNMET_SYSTEM_REQUIREMENTS          = 0x2
FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION = 0x4
FW_EXIT_CODE_ERROR_ABORTED_BY_USER                    = 0x8

hard_checkers = [
    { 'hard_check_sse42'              : [ True , 'critical' , 'support in SSE 4.2 is required' ] },
    { 'hard_check_ram'                : [ 4 ,    'critical' , 'at least 4GB RAM is required' ] },
    { 'hard_check_cpu_number'         : [ 2,     'critical' , 'at least 2 logical CPU-s are required' ] },
    { 'hard_check_nic_number'         : [ 2,     'critical' , 'at least 2 Network Interfaces are required' ] },
    { 'hard_check_nic_drivers'        : [ True , 'optional' , 'supported network cards' ] },
    { 'hard_check_kernel_io_modules'  : [ True , 'optional' , 'kernel has i/o modules' ] },
    { 'hard_check_wan_connectivity'   : [ True , 'optional' , 'WAN connectivity is required' ] },
    { 'hard_check_default_route_connectivity' : [ True, 'optional' ,  'default route should have WAN connectivity' ] }
]

soft_checkers = [
    { 'soft_check_uuid'               : { 'severity': 'critical' }},
    { 'soft_check_hostname_syntax'    : { 'severity': 'critical' , 'interactive': 'must' }},   # This check should be before 'soft_check_hostname_in_hosts', as last might insert bad syntax hostname into /etc/hosts file
    { 'soft_check_hostname_in_hosts'  : { 'severity': 'critical' }},
    { 'soft_check_default_route'      : { 'severity': 'critical' , 'interactive': 'must' }},
    {'soft_check_multiple_interface_definitions': {'severity': 'critical'}},
    {'soft_check_duplicate_netplan_sections': {'severity': 'critical'}},
    { 'soft_check_default_routes_metric'         : { 'severity': 'critical' }},
    { 'soft_check_resolvconf'         : { 'severity': 'optional' }},
    { 'soft_check_networkd'           : { 'severity': 'critical' }},
    { 'soft_check_utc_timezone'       : { 'severity': 'critical' }},
    { 'soft_check_disable_linux_autoupgrade'     : { 'severity': 'critical' }},
    { 'soft_check_disable_transparent_hugepages' : { 'severity': 'optional' }},
    { 'soft_check_hugepage_number'    : { 'severity': 'optional' , 'interactive': 'optional' }},
    { 'soft_check_dpdk_num_buffers'   : { 'severity': 'optional' , 'interactive': 'optional' }},
	{ 'soft_check_vpp_workers_core'   : { 'severity': 'optional' , 'interactive': 'optional' }},
    { 'soft_check_cpu_power_saving' : { 'severity': 'optional' , 'interactive': 'optional' }}

]

class TXT_COLOR:
    BG_SUCCESS          = '\x1b[30;42m'  # Green
    BG_FAILURE_CRITICAL = '\x1b[30;41m'  # Red
    BG_FAILURE_OPTIONAL = '\x1b[30;43m'  # Yellow
    FG_SUCCESS          = '\x1b[32m'       # Green
    FG_FAILURE_CRITICAL = '\x1b[31m'       # Red
    FG_FAILURE_OPTIONAL = '\x1b[33m'       # Yellow
    FG_BOLD             = '\x1b[1m'
    FG_UNDERLINE        = '\x1b[4m'
    END                 = '\x1b[0m'

def checker_name_to_description(checker_name):
    """Convert checker name into description.

    :param checker_name:         Checker name.

    :returns: Description.
    """
    return ' '.join(checker_name.split('_')[1:])

def report_checker_result(succeeded, severity, checker_name, description=None):
    """Report checker results.

    :param succeeded:       Success status.
    :param severity:        Severity level.
    :param checker_name:    Checker name.
    :param description:     Description.

    :returns: None.
    """
    if not description:
        description = checker_name_to_description(checker_name)
    if succeeded:
        status   = TXT_COLOR.FG_SUCCESS + ' PASSED ' + TXT_COLOR.END
    else:
        if severity == 'optional':
            status   = TXT_COLOR.BG_FAILURE_OPTIONAL + ' FAILED ' + TXT_COLOR.END
        else:
            status   = TXT_COLOR.BG_FAILURE_CRITICAL + ' FAILED ' + TXT_COLOR.END
    print('%s: %s : %s' % (status, severity.upper(), description))

def check_hard_configuration(checker, check_only):
    """Check hard configuration.

    :param checker:         Checker name.
    :param check_only:      Check only mode.

    :returns: 'True' if succeeded.
    """
    succeeded = True
    for element in hard_checkers:
        (checker_name, checker_params) = element.items()[0]

        # Don't run connectivity checkers in check only mode,
        # as every check waits 5 seconds for ping response on every found interface.
        # That might suspend agent start too long, making user experience bad.
        if 'connectivity' in checker_name and check_only:
            continue

        checker_func = getattr(checker, checker_name)
        args         = checker_params[0]
        severity     = checker_params[1]
        description  = checker_params[2]
        result = checker_func(args)
        if not result and severity == 'critical':
            succeeded = False
        report_checker_result(result, severity, checker_name, description)
    return succeeded

def check_soft_configuration(checker, fix=False, quiet=False):
    """Check hard configuration.

    :param checker:         Checker name.
    :param fix:             Fix problem.
    :param quiet:           Do not prompt user.

    :returns: 'True' if succeeded.
    """
    succeeded = True
    for element in soft_checkers:

        (checker_name, checker_params) = element.items()[0]
        prompt = checker_name_to_description(checker_name) + ': '

        checker_func = getattr(checker, checker_name)
        severity     = checker_params['severity']
        result       = checker_func(fix=False, prompt=prompt)
        report_checker_result(result, severity, checker_name)

        go_and_fix = fix
        if go_and_fix:
            # No need to fix if result is OK.
            if result:
                go_and_fix = False

            interactive = '' if not 'interactive' in checker_params \
                             else checker_params['interactive']

            # If parameter is adjustable and interactive mode was chosen,
            # fix the parameter even if result is OK. This is to provide
            # user with ability to change default configuration.
            if result and not quiet and interactive == 'optional':
                go_and_fix = True

            # Don't fix if silent was specified but user interaction is required
            if not result and quiet and interactive == 'must':
               go_and_fix = False

        if not go_and_fix:
            if not result and severity == 'critical':
                succeeded = False
            continue

        if quiet:
            result = checker_func(fix=True, silently=True, prompt=prompt)
            report_checker_result(result, severity, checker_name)
        else:
            while True:
                choice = raw_input(prompt + "configure? [y/N/q]: ")
                if choice == 'y' or choice == 'Y':
                    result = checker_func(fix=True, silently=False, prompt=prompt)
                    report_checker_result(result, severity, checker_name)
                    break
                elif choice == 'n' or choice == 'N' or choice == '':
                    break
                elif choice == 'q' or choice == 'Q':
                    exit(FW_EXIT_CODE_ERROR_ABORTED_BY_USER)
        if not result and severity == 'critical':
            succeeded = False
    return succeeded

def reset_system_to_defaults(checker):
    """ reset vpp configuration to default

    :returns: 'True' if succeeded.
    """ 
    # This function does the following:
    # 1. Copies the startup.conf.orig over the start.conf and startup.conf.baseline files.
    # 2. reset /etc/default/grub to a single core configuration
    # 3. Reboot.

    reboot_needed = False
    while True:
        choice = raw_input("Resetting to Factory Defauls. Resetting will reboot the system. Are you sure? [y/N]: ")
        if choice == 'n' or choice == 'N' or choice == '':
            return True
        elif choice == 'y' or choice == 'Y':
            shutil.copyfile (fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE)
            if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
                shutil.copyfile (fwglobals.g.VPP_CONFIG_FILE_RESTORE, fwglobals.g.VPP_CONFIG_FILE_BACKUP)
            checker.update_grub = True
            checker.update_grub_file()
            reboot_needed = True
            break
    
    if reboot_needed == True:
        while True:
            choice = raw_input("Reboot the system? [Y/n]: ")
            if choice == 'n' or choice == 'N':
                print ("Please reboot the system for changes to take effect.")
                return True
            elif choice == 'y' or choice == 'Y' or choice == '':
                print ("Rebooting....")
                os.system('reboot now')
    return True

def main(args):
    """Checker entry point.

    :param args:            Command line arguments.

    :returns: Bitmask with status codes.
    """
    (flavor, version, _) = platform.linux_distribution()
    module_name = (flavor + version.replace('.', '')).lower()
    module = importlib.import_module(module_name)
    with module.Checker(args.debug) as checker:

        # Check hardware requirements
        # -----------------------------------------
        hard_status_code = FW_EXIT_CODE_OK
        if not args.soft_only:
            if not args.hard_only:
                print('\n=== hard configuration ====')
            success = check_hard_configuration(checker, args.check_only)
            hard_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_UNMET_HARDWARE_REQUIREMENTS
            if args.hard_only:
                return hard_status_code

        # Check software and configure it if needed
        # -----------------------------------------
        if not (args.hard_only or args.soft_only):
            print('\n=== soft configuration ====')
        if args.check_only:
            success = check_soft_configuration(checker, fix=False)
            soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_UNMET_SYSTEM_REQUIREMENTS
            if not success:
                print('')
                print("===================================================================================")
                print("! system checker errors, run 'fwsystem_checker' with no flags to fix configuration!")
                print("===================================================================================")
                print('')
            return (soft_status_code | hard_status_code)

        if args.quiet:
            # In silent mode just go and configure needed stuff
            success = check_soft_configuration(checker, fix=True, quiet=True)
            soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION
            return  (soft_status_code | hard_status_code)

        # Firstly show to user needed configuration adjustments.
        # The start intercation with user.
        check_soft_configuration(checker, fix=False)
        choice = 'x'
        while not (choice == '' or choice == '0' or choice == '4'):
            choice = raw_input(
                            "\n" +
                            "\t[0] - quit and use fixed parameters\n" +
                            "\t 1  - check system configuration\n" +
                            "\t 2  - configure system silently\n" +
                            "\t 3  - configure system interactively\n" +
                            "\t 4  - restore system to factory defaults\n" +
                            "\t-----------------------------------------\n" +
                            "Choose: ")
            if choice == '1':
            	print('')
                success = check_soft_configuration(checker, fix=False)
            elif choice == '2':
            	print('')
                success = check_soft_configuration(checker, fix=True, quiet=True)
            elif choice == '3':
            	print('')
                success = check_soft_configuration(checker, fix=True, quiet=False)
            elif choice == '4':
                print ('')
                success = reset_system_to_defaults(checker)
            else:
                success = True

        if choice == '0' or choice == '':   # Note we restart daemon and not use 'fwagent restart' as fwsystem_checker might change python code too ;)
	        if success == True:
                    print ("Please wait..")
                    os.system("sudo systemctl stop flexiwan-router")
                    checker.save_config()
                    if checker.update_grub == True:
		                rebootSys = 'x'
                                while not (rebootSys == "n" or rebootSys == 'N' or rebootSys == 'y' or rebootSys == 'Y'): 
                                    rebootSys = raw_input("Changes to OS confugration requires system reboot.\n" +
                                                    "Would you like to reboot now (Y/n)?")
                                    if rebootSys == 'y' or rebootSys == 'Y' or rebootSys == '':
                                        print ("Rebooting...")
                                        os.system('reboot now')
                                    else:
                                        print ("Please reboot the system for changes to take effect.")

                os.system("sudo systemctl start flexiwan-router")
                print ("Done.")
		
        soft_status_code = FW_EXIT_CODE_OK if success else FW_EXIT_CODE_ERROR_FAILED_TO_FIX_SYSTEM_CONFIGURATION
        return (soft_status_code | hard_status_code)

if __name__ == '__main__':
    import argparse
    global arg

    parser = argparse.ArgumentParser(description='FlexiEdge configuration utility')
    parser.add_argument('-c', '--check_only', action='store_true',
                        help="check configuration and exit")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="adjust system configuration silently")
    parser.add_argument('-r', '--hard_only', action='store_true',
                        help="check hard configuration only")
    parser.add_argument('-s', '--soft_only', action='store_true',
                        help="check soft configuration only")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="don't clean temporary files and enable debug prints")
    args = parser.parse_args()
    res = main(args)
    ####### For now (Dec-2019) don't block installation and agent start on failure
    # exit(res)
    exit(FW_EXIT_CODE_OK)
