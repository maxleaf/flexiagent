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
# Than it injects 'sync-device' request out of step2_X.cli file  with special
# attribute: "type": "full-sync". This is to enforce full sync in case the agent
# sees no need in it. The full sync stops VPP, resets the configuration database
# to be empty, loads configuration items out of the 'sync-device' message into
# it and starts VPP.
# At every step test ensures that resulted VPP configuration and configuration
# database dump match the expected VPP configuration and dump.
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
            (ok, err_str) = agent.cli('-f %s' % step,
                                    daemon=daemon,
                                    expected_vpp_cfg=expected_vpp_cfg[idx],
                                    expected_router_cfg=expected_dump_cfg[idx],
                                    check_log=True)
            assert ok, err_str


        # Ensure smart and full sync are noted in log
        #
        lines = agent.grep_log('smart sync', print_findings=False)
        assert len(lines) > 0, "log has no mention of smart sync: %s" % '\n'.join(lines)
        lines = agent.grep_log('full sync', print_findings=False)
        assert len(lines) > 0, "log has no mention of full sync: %s" % '\n'.join(lines)

        # Ensure that VPP was restarted twice during test.
        # In this case the log should have three following lines:
        #     Aug  2 06:13:03 localhost fwagent: router was started: vpp_pid=...
        # The 1st - for start with initial configuration
        # The 2nd - for start after smart sync
        # The 3rd - for start after full sync
        #
        lines = agent.grep_log('router was started: vpp_pid=', print_findings=False)
        assert len(lines) == 3, "log has not expected number of VPP starts (expected 3): %d:%s" % \
                                (len(lines), '\n'.join(lines))

        # Ensure that the configuration database signature was reset as a result of 'sync-device'
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        assert ok, ret
        cfg_signature = ret.get('router-cfg-hash')
        assert cfg_signature == '', "signature was not reset on 'sync-device' success: %s" % cfg_signature


if __name__ == '__main__':
    test()
