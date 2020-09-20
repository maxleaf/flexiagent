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

hard_checks = [
    { 'hard_check_sse42'              : [ True , 'critical' , 'support in SSE 4.2 is required' ] },
    { 'hard_check_ram'                : [ 4 ,    'critical' , 'at least 4GB RAM is required' ] },
    { 'hard_check_cpu_number'         : [ 2,     'critical' , 'at least 2 logical CPU-s are required' ] },
    { 'hard_check_nic_number'         : [ 2,     'critical' , 'at least 2 Network Interfaces are required' ] },
    { 'hard_check_nic_drivers'        : [ True , 'optional' , 'supported network cards' ] },
    { 'hard_check_kernel_io_modules'  : [ True , 'optional' , 'kernel has i/o modules' ] },
    { 'hard_check_wan_connectivity'   : [ True , 'optional' , 'WAN connectivity is required' ] },
    { 'hard_check_default_route_connectivity' : [ True, 'optional' ,  'default route should have WAN connectivity' ] }
]

soft_checks = [
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

def check_name_to_description(check_name):
    """Convert check name into description.

    :param check_name:         check name.

    :returns: Description.
    """
    return ' '.join(check_name.split('_')[1:])

def report_results(results):
    """Goes over list of check results and for each of them print information
    regarding check and it result onto screen.
    The list elements are dictionary of following format:
        { <check_name>: {
            'result': <False on failure/True on success>,
            'current_value': <checked value if applicable, e.g. found RAM in GB>,
            'severity':      <severity taken from hard_checks/soft_checks>,
            'description':   <description if the check taken from hard_checks/soft_checks>
          }
        }

    :param results: List of checks and results

    :returns: True if all critical checks succeeded, False otherwise.
    """
    success = True
    for element in results:
        (check_name, result_params) = element.items()[0]
        succeeded   = result_params.get('result', False)
        value       = result_params.get('value', '')
        severity    = result_params.get('severity')
        description = result_params.get('description')

        if not description:
            description = check_name_to_description(check_name)
        if succeeded:
            status = TXT_COLOR.FG_SUCCESS + ' PASSED ' + TXT_COLOR.END
        else:
            if severity == 'optional':
                status = TXT_COLOR.BG_FAILURE_OPTIONAL + ' FAILED ' + TXT_COLOR.END
            else:
                status = TXT_COLOR.BG_FAILURE_CRITICAL + ' FAILED ' + TXT_COLOR.END
        print('%s: %s : %s (found: %s)' % \
            (status, severity.upper(), description, str(value)))

        if not succeeded and severity == 'critical':
            success = False

    return success


def check_hard_configuration(checker, escape):
    """Check hard configuration.

    :param check:  The Checker object that implements check methods.
    :param escape: The list of checks that should not be run.

    :returns: list of checks with results and found values.
    """
    results = []
    for element in hard_checks:
        (check_name, check_params) = element.items()[0]

        if check_name in escape:
            continue

        check_func   = getattr(checker, check_name)
        expected_val = check_params[0]
        severity     = check_params[1]
        description  = check_params[2]

        (result, found_val) = check_func(expected_val)

        results.append({check_name: {
            'result': result, 'value': found_val, 'severity': severity,
            'description': description}})
    return results

def check_soft_configuration(check, fix=False, quiet=False):
    """Check hard configuration.

    :param check: check object inhereted from fwsystem_check_common.check.
                    For example, ubuntu1804.check.
    :param fix:     Fix problem.
    :param quiet:   Do not prompt user.

    :returns: 'True' if succeeded.
    """
    succeeded = True
    for element in soft_checks:

        (check_name, check_params) = element.items()[0]
        prompt = check_name_to_description(check_name) + ': '

        check_func = getattr(check, check_name)
        severity     = check_params['severity']
        result       = check_func(fix=False, prompt=prompt)
        report_check_result(result, severity, check_name)

        go_and_fix = fix
        if go_and_fix:
            # No need to fix if result is OK.
            if result:
                go_and_fix = False

            interactive = '' if not 'interactive' in check_params \
                             else check_params['interactive']

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
            result = check_func(fix=True, silently=True, prompt=prompt)
            report_check_result(result, severity, check_name)
        else:
            while True:
                choice = raw_input(prompt + "configure? [y/N/q]: ")
                if choice == 'y' or choice == 'Y':
                    result = check_func(fix=True, silently=False, prompt=prompt)
                    report_check_result(result, severity, check_name)
                    break
                elif choice == 'n' or choice == 'N' or choice == '':
                    break
                elif choice == 'q' or choice == 'Q':
                    exit(FW_EXIT_CODE_ERROR_ABORTED_BY_USER)
        if not result and severity == 'critical':
            succeeded = False
    return succeeded

def reset_system_to_defaults(check):
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
            check.update_grub = True
            check.update_grub_file()
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
    """check entry point.

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

            # If runs in --check_only mode don't run checks that might take time,
            # like connectivity check which  might take 5 seconds for pinging
            # every found interface. This is to avoid delay on agent start to
            # keep positive user experience.
            #
            escape = []
            if args.check_only:
                escape = [ 'hard_check_wan_connectivity', 'hard_check_default_route_connectivity']

            results = check_hard_configuration(checker, escape)
            success = report_results(results)
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
                print("! system check errors, run 'fwsystem_check' with no flags to fix configuration!")
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

        if choice == '0' or choice == '':   # Note we restart daemon and not use 'fwagent restart' as fwsystem_check might change python code too ;)
	        if success == True:
                    print ("Please wait..")
                    os.system("sudo systemctl stop flexiwan-router")
                    check.save_config()
                    if check.update_grub == True:
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

    # Ensure that VPP does not run.
    # Otherwise driver interface checks might fail and user will be scared for
    # no reason. Note it is too late to check system, if router was started :)
    #
    try:
        pid = subprocess.check_output(['pidof', 'vpp'])
        # If we reached this point, i.e. if no exception occurred, the vpp pid was found
        print ("error: router runs (pid=%s), too late to check the system" % pid)
        exit(FW_EXIT_CODE_OK)
    except:
        pass


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
