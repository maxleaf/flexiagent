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

import glob
import os
import re
import sys
import shutil

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
multiple_netplan = os.path.join(cli_path, 'multiple_netplans/')

def test():
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    yaml_config = sorted(glob.glob('%s/*.yaml' % tests_path))
    orig_yaml = glob.glob("/etc/netplan/50*.yaml")
    #take backup of original netplan yaml file
    orig_backup = orig_yaml[0].replace('yaml', 'yaml.backup')
    shutil.move(orig_yaml[0], orig_backup)
    for yaml in yaml_config:
        
        for t in test_cases:
            #copy the netplan file to netplan dir
	    if 'multiple_netplan' in yaml:
                os.system('cp -R %s* /etc/netplan/' % multiple_netplan) 
            else:
	        shutil.copy(yaml, '/etc/netplan/50-cloud-init.yaml')
	        #apply netplan
	        os.system('netplan apply')
            with fwtests.TestFwagent() as agent:
                print("   " + os.path.basename(t))

		agent.cli('-f %s' % cli_start_router_file)
                # Load router configuration with spoiled lists
                agent.cli('--api inject_requests filename=%s ignore_errors=True' % t)

                # Ensure that spoiled lists were reverted completely
                configured = fwtests.wait_vpp_to_be_configured([('interfaces', 0),('tunnels', 0)], timeout=30)
                assert configured

                agent.cli('-f %s' % cli_stop_router_file)

            os.system('rm -f /etc/netplan/*.yaml')
    #restoring the original yaml file
    #orig_backup = orig_yaml[0].replace('yaml.backup', 'yaml')
    shutil.move(orig_backup, orig_yaml[0])
if __name__ == '__main__':
    test()
