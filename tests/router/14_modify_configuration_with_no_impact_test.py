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
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_get_device_stats_file  = os.path.join(cli_path, 'get_device_stats.cli')

################################################################################
# This test feeds agent with router configuration out of step1_X.cli file.
# Than it injects a number of 'aggregated' requests each of them include list of
# 'modify-X' requests that should NOT cause update of VPP configuration.
# For example, the 'modify-interface' request that modifies 'publicIp' parameter
# should not be executed, as it has no impact on VPP. It just should be saved
# in the router configuration database, so STUN module could uses it for
# the STUN related logic.
#
# Every injected 'aggregated' request is named a 'step'.
#   After every step test ensures that resulted router configuration database
# matches the expected dump of the router configuration. As well it ensures,
# that agent log has no mention of reconnection to flexiManage and no mention
# of request execution.
################################################################################
def test():
    with fwtests.TestFwagent() as agent:

        steps             = sorted(glob.glob(cli_path + '/' + 'step*.cli'))
        expected_dump_cfg = sorted(glob.glob(cli_path + '/' + 'step*dump*.json'))

        for (idx,step) in enumerate(steps):

            # The first step just starts router with initial configuration and
            # does not require flashy checks.
            #
            if idx == 0:
                print("")
                print("   " + os.path.basename(step))
                (ok, error_str) = agent.cli('-f %s' % step, daemon=True)
                assert ok, error_str
                time.sleep(1)               # Ensure difference in time between the first and the further steps
                agent.set_log_start_time()  # mark log start. It is needed for checks on log run by further steps
                continue

            print("   " + os.path.basename(step))
            (ok, _) = agent.cli('-f %s' % step)
            assert ok, "failed to inject %s" % step

            # Ensure validity of database configurations.
            #
            router_configured = fwtests.router_is_configured(expected_dump_cfg[idx], fwagent_py=agent.fwagent_py)
            assert router_configured, "configuration dump does not match %s" % expected_dump_cfg[idx]

            # Ensure no mention of command execution in log
            #
            lines = agent.grep_log('execute')
            assert len(lines) == 0, "'execute' found in log: %s" % '\n'.join(lines)

            # Ensure no mention of reconnection to flexiManage in log
            #
            lines = agent.grep_log('connect')
            assert len(lines) == 0, "'connect' found in log: %s" % '\n'.join(lines)

            # Ensure no errors in log
            #
            lines = agent.grep_log('error: ')
            assert len(lines) == 0, "errors found in log: %s" % '\n'.join(lines)


if __name__ == '__main__':

    test()