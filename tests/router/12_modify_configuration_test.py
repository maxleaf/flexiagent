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
cli_get_device_stats_file  = os.path.join(cli_path, 'get_device_stats.cli')

################################################################################
# This test feeds agent with router configuration out of step1_X.cli file.
# Than it injects a number of 'aggregated' requests each of them include list of
# 'add-X', 'remove-X' and 'modify-X' requests to test modification of router
# configuration.
# Every injected 'aggregated' request is named a 'step'.
#   After every step test ensures that resulted VPP configuration and
# configuration database dump match the expected VPP configuration and dump.
#   As well test ensures that vpp is restarted if needed after modificaion.
# For example the 'add-interface' and 'remove-interface' requests require vpp
# restart.
################################################################################
def test():
    with fwtests.TestFwagent() as agent:

        steps             = sorted(glob.glob(cli_path + '/' + 'step*.cli'))
        expected_vpp_cfg  = sorted(glob.glob(cli_path + '/' + 'step*vpp*.json'))
        expected_dump_cfg = sorted(glob.glob(cli_path + '/' + 'step*dump*.json'))

        for (idx,step) in enumerate(steps):

            if idx == 0:
                print("")
            print("   " + os.path.basename(step))

            # Inject request.
            # Note the first request comes with 'daemon=True' to leave agent
            # running on background, so it could receive further injects.
            #
            daemon = True if idx == 0 else False
            (ok, _) = agent.cli('-f %s' % step, daemon=daemon)
            assert ok

            # Ensure validity of VPP and database configurations.
            #
            vpp_configured = fwtests.wait_vpp_to_be_configured(expected_vpp_cfg[idx], timeout=30)
            assert vpp_configured, "VPP configuration does not match %s" % expected_vpp_cfg[idx]
            router_configured = fwtests.router_is_configured(expected_dump_cfg[idx], fwagent_py=agent.fwagent_py)
            assert router_configured, "configuration dump does not match %s" % expected_dump_cfg[idx]

            # Ensure no errors in log
            #
            lines = agent.grep_log('error: ')
            assert len(lines) == 0, "errors found in log: %s" % '\n'.join(lines)

        # Ensure that vpp was restarted if needed.
        # For now only steps #4, #5 and #6 require restarts, so we expect 3
        # vpp starts to be printed in log for this steps. And one more start
        # for initial configuration - step #1.
        #
        lines = agent.grep_log('router was started: vpp_pid=', print_findings=False)
        assert len(lines) == 4, "log has not expected number (4) of VPP starts: %d:%s" % \
                                (len(lines), '\n'.join(lines))


if __name__ == '__main__':
    test()
