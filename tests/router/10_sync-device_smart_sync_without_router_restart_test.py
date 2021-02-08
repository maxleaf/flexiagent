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

import datetime
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
# Than it injects a number of 'sync-device' requests to test smart
# synchronization that does not require VPP restart. The restart is not required
# neither new interfaces should be added nor existing interfaces should be
# removed in order to get in sync.
# Every injected 'sync-device' request is named a 'step'.
#   After every step test ensures that resulted VPP configuration and
# configuration database dump match the expected VPP configuration and dump.
#   As well test ensures that no fallback to full sync happend. Note in smart
# sync only affected configuration items are handled. In full sync
# the configuration is reset and all configuration items received within
# 'sync-device' request are loaded and executed.
#
# Below are steps that this test consists of:
#   step1_cfg_initial.cli - loads all kind of configuration items - interfaces,
#       tunnels, routes, applications, multilink policies, DHCP servers, etc.
#   step2_cfg_donttouch_modify_add_remove_opposite_order.cli - performs all kind
#       of possible configuration adjustments for all kinds of configuration
#       items - addition, removal, modifications, not-touching (no modifications).
#       That does not include adding and removal interfaces in order to prevent
#       vpp restart. The interface modifying and not-touching are tested.
#       The order of configuration items (add-X requests) in 'sync-device' is
#       opposite to the order sent by server usually. This is subject for test,
#       as order of synchronization is important! For example, the tunnels
#       should be removed before interfaces used by them, etc.
#   step3_cfg_donttouch_modify_add_remove_usual_order.cli - same as step 2,
#       but 'sync-device' contains configuration items (add-X) requests in order
#       which is used usually by flexiManage. It is opposite to the order in
#       step 2.
#   step4_cfg_remove_tunnels_only.cli - the result of sync is removal of tunnels
#       only. All the rest should be not touched.
#   step5_cfg_add_tunnels_only.cli - the result of sync is addition of tunnels
#       only. All the rest should be not touched.
#   step6_cfg_modify_tunnels_only.cli - the result of sync is modification of
#       tunnels only. All the rest should be not touched.
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

            step_start_time = datetime.datetime.now()

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

            # Ensure smart sync is noted in log.
            # Note the first step does not perform sync, but loads initial
            # configuration only, hence no need to perform checks below.
            #
            if idx > 0:
                lines = agent.grep_log('smart sync', print_findings=False)
                assert len(lines) > 0, "log has no mention of smart sync: %s" % '\n'.join(lines)

                # Ensure full sync is not noted in log
                #
                lines = agent.grep_log('full sync', print_findings=False)
                assert len(lines) == 0, "unexpected full sync: %s" % '\n'.join(lines)

                # Ensure that the configuration database signature was reset as a result of 'sync-device'
                #
                (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
                assert ok, ret
                cfg_signature = ret.get('router-cfg-hash')
                assert cfg_signature == '', "signature was not reset on 'sync-device' success: %s" % cfg_signature

                # Ensure that VPP was not restarted even once during test.
                # In this case the log should have only one notion of vpp start -
                # on loading initial configuration:
                #     Aug  2 06:13:03 localhost fwagent: router was started: vpp_pid=...
                #
                lines = agent.grep_log('router was started: vpp_pid=', print_findings=False)
                assert len(lines) == 1, "log has not expected number of VPP starts: %d:%s" % \
                                        (len(lines), '\n'.join(lines))

                # Ensure that smart sync is indeed smart: it should reconfigure
                # only delta between 'sync-device' content and current
                # configuration. Step6 modifies 3 tunnels. So we should see 6
                # executed requests in log: 3 'remove-tunnel'-s and 3 'add-tunnel'-s.
                #
                if idx == 5:  # step6_cfg_modify_tunnels_only.cli
                    lines = agent.grep_log('=== start execution of ', print_findings=False, since=step_start_time)
                    assert len(lines) == 6, "log has not expected number of sync requests: %d:%s" % \
                                            (len(lines), '\n'.join(lines))

if __name__ == '__main__':
    test()
