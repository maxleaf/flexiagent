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
import subprocess
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')

def test():
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    for t in test_cases:
        with fwtests.TestFwagent() as agent:
            print("   " + os.path.basename(t))

            # Load router configuration with spoiled lists
            agent.cli('--ignore_errors -f %s' % t)
            # Ensure that spoiled lists were reverted completely
            configured = fwtests.wait_vpp_to_be_configured([('interfaces', 0),('tunnels', 0)], timeout=30)
            assert configured

            # For route test only: ensure that route table has no routes
            # that *_list_routes.cli tried to add from list, but failed
            # and reverted them.
            if re.search('list_routes', os.path.basename(t)):
                routes = subprocess.check_output("ip route", shell=True)
                assert routes.find('6.6.6.') == -1, "route for 6.6.6.X was not reverted"
                assert routes.find('9.9.9.') == -1, "route for 9.9.9.X was not reverted"

            agent.cli('-f %s' % cli_stop_router_file)


if __name__ == '__main__':
    test()
