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

import json
import glob
import os
import subprocess
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')

################################################################################
# This test runs agent as a daemon, than injects into it router configuration
# out of <cli_start_router_file> that includes all configuration items like
# interfaces, tunnels, dhcp-server, routes, applications, multilink-policies, etc.
# Than it restarts the agent daemon, causing thus reset and restore of global
# variables. Than it removes some configuration items and adds them back,
# ensuring proper restore of global data and successful post restart configuration.
################################################################################
def test():
    with fwtests.TestFwagent() as agent:

        # Now go and execute rest steps - add/remove configuration, etc.
        #
        steps             = sorted(glob.glob(cli_path + '/' + 'step*.cli'))
        expected_vpp_cfg  = sorted(glob.glob(cli_path + '/' + 'step*vpp*.json'))
        expected_dump_cfg = sorted(glob.glob(cli_path + '/' + 'step*dump*.json'))

        for (idx,step) in enumerate(steps):

            if idx == 0:
                print("")
            print("   " + os.path.basename(step))

            daemon = True if idx == 0 or idx == 1 else False

            # Execute step and ensure proper configuration afterwards
            #
            (ok, err_str) = agent.cli('-f %s' % steps[idx],
                                    daemon=daemon,
                                    expected_vpp_cfg=expected_vpp_cfg[idx],
                                    expected_router_cfg=expected_dump_cfg[idx])
            assert ok, err_str

            # Kill the daemon after the initial configuration step (step 1)
            #
            if idx == 0:
                daemon_pid = fwtests.fwagent_daemon_pid()
                assert daemon_pid, "agent daemon pid was not found!"
                os.system('kill -9 %s' % daemon_pid)

            # Ensure no errors in log
            #
            lines = agent.grep_log('error: ')
            assert len(lines) == 0, "errors found in log: %s" % '\n'.join(lines)

if __name__ == '__main__':
    test()
