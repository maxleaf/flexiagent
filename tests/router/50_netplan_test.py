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
import re
import sys
import shutil
import macDynamic

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
multiple_netplan = os.path.join(cli_path, 'multiple_netplans/')

def test(netplan_backup):
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    yaml_config = sorted(glob.glob('%s/*.yaml' % tests_path))
    orig_yaml = glob.glob("/etc/netplan/50*.yaml")
    for yaml in yaml_config:
        print("Netplan :: %s" % yaml.split('/')[-1])
        for test in [t for t in test_cases if t not in [cli_stop_router_file, cli_start_router_file]]:
            #copy the netplan file to netplan dir
            if 'multiple_netplan' in yaml:
                os.system('cp -R %s* /etc/netplan/' % multiple_netplan)
                #To update the MAC address in the yaml files, uncomment the function below
                #Please note that 2 modules: getmac and netifaces have to be installed 
                #macDynamic.convertMacAddress() 
            else:
                shutil.copy(yaml, '/etc/netplan/50-cloud-init.yaml')
            #apply netplan
            os.system('netplan apply')

            with fwtests.TestFwagent() as agent:
                print("   " + os.path.basename(test))
                (ok, out) = agent.cli('-f %s' % cli_start_router_file)
                assert ok
                print("start_router: %s" % out)

                # Load router configuration with spoiled lists
                (ok, out) = agent.cli('--api inject_requests filename=%s ignore_errors=False' % test)
                assert ok
                print("Inject cli '%s': %s" %(os.path.basename(test),out))
                (ok, out) = agent.cli('-f %s' % cli_stop_router_file)
                assert ok
                print("stop_router: %s" % out)
            os.system('rm -f /etc/netplan/*.yaml')

if __name__ == '__main__':
    test()
