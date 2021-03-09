################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
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
#
################################################################################

"""
This is a whitebox script to test netplan under different scenarios and with
 combination of netplans.
 The script start with loading a initial configuration in netplan. These initial
 configurations are:
 - Basic netplan with all interfaces
 - Multiple netplan files for different interfaces
 - With metrics configuration in netplan and without as static and as dhcp
 - Use default route in netplan configuration and without
 - Use match in netplan and set name
 - Use incomplete configurations in netplan
 After loading the initial configuration the script will start the loading test
 configurations which are:
 1) two WANs + LAN,
 2) two LANs + WAN,
 3) One WAN + One LAN + Unassigned
 4) Two dhcp + One Static
 After each test the initial netplan file is again loaded.

 Test Environment : This test has to be run on a Ubuntu 18.04 Virtualbox with
 3 intf: 0000:00:03.0, 0000:00:08.0 and 0000:00:09.0

 REMEMBER TO STOP THE ROUTER BEFORE RUNNING THE SCRIPT

 Use : sudo systemctl stop flexiwan-router

 To run the script : pytest -s -k 13
"""
import glob
import os
import sys
import shutil
import fwtests

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(TEST_ROOT)

CLI_PATH = __file__.replace('.py', '')
CLI_STOP_ROUTER = os.path.join(CLI_PATH, 'stop-router.cli')
CLI_START_ROUTER = os.path.join(CLI_PATH, 'start-router.cli')
MULTIPLE_NETPLAN = os.path.join(CLI_PATH, 'multiple_netplans/')

# pylint: disable-msg=unused-argument
# These are unused arguments are fixture name contains in conftest.py file
def test_netplan(netplan_backup):
    '''
    This tests netplan under different scenarios, with combination of netplans
    '''
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    yaml_config = sorted(glob.glob('%s/*.yaml' % tests_path))
    for yaml in yaml_config:
        # if '07' in yaml:
        #     continue
        print "Netplan :: %s" % yaml.split('/')[-1]
        for test in [t for t in test_cases if t not in \
            [CLI_STOP_ROUTER, CLI_START_ROUTER]]:
            #copy the netplan file to netplan dir
            if 'multiple_netplan' in yaml:
                os.system('cp -R %s* /etc/netplan/' % MULTIPLE_NETPLAN)
            else:
                shutil.copy(yaml, '/etc/netplan/50-cloud-init.yaml')
            #apply netplan
            fwtests.adjust_environment_variables()
            os.system('netplan apply')

            with fwtests.TestFwagent() as agent:
                (start_ok, out) = agent.cli('-f %s' % CLI_START_ROUTER)
                assert start_ok, "Failed to start router"
                lines = agent.grep_log('Exception: API failed')
                assert len(lines) == 0, "Error in start router: %s" % '\n'.join(lines)

                # Load router configuration with spoiled lists
                (cli_ok, out) = agent.cli('-f %s' % test) #ignore_errors=False
                assert cli_ok, "Failed to inject request with %s file" % test
                lines = agent.grep_log('Exception: API failed')
                assert len(lines) == 0, "Errors in %s cli: %s" %(test, '\n'.join(lines))

                (stop_ok, out) = agent.cli('-f %s' % CLI_STOP_ROUTER)
                assert stop_ok, "Failed to stop router"
                lines = agent.grep_log('Exception: API failed')
                assert len(lines) == 0, "Error in stop router: %s" % '\n'.join(lines)

            os.system('rm -f /etc/netplan/*.yaml')

if __name__ == '__main__':
    test_netplan()
