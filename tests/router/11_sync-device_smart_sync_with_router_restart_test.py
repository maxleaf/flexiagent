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
# Than it injects a number of 'sync-device' requests to test smart
# synchronization that does require VPP restart. The restart is required
# when either new interfaces is added or existing interfaces is removed in order
# to get in sync with flexiManage.
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
#       That includes adding and removal interfaces in order to prevent vpp
#       restart. The order of configuration items (add-X requests) in
#       'sync-device' is opposite to the order sent by server usually. This is
#       subject for test, as order of synchronization is important! For example,
#       the tunnels should be removed before interfaces used by them, etc.
#   step3_cfg_donttouch_modify_add_remove_usual_order.cli - same as step 2,
#       but 'sync-device' contains configuration items (add-X) requests in order
#       which is used usually by flexiManage. It is opposite to the order in
#       step 2.
#   step4_cfg_remove_tunnels_and_one_interface.cli - the result of sync is
#       removal of tunnels and one interface only.
#       touched. We have to remove interface in order to cause vpp restart.
#       Note we have to remove multilink-policy as it might use interfaces.
#   step5_cfg_remove_interfaces.cli - the result of sync is
#       removal of all interfaces. Note we have to remove dhcp-config as well,
#       as they require LAN interface. That leaves us with applications only.
#   step6_cfg_add_interfaces_only.cli - the result of sync is addition of
#       interfaces only.
#   step7_cfg_add_tunnels_and_one_interface_only.cli - the result of sync is
#       addition of tunnels and one interface only. All the rest should be not
#       touched. We have to add interface in order to cause vpp restart.
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
                cfg_signature = ret.get('router-cfg-hash')
                assert cfg_signature == '', "signature was not reset on 'sync-device' success: %s" % cfg_signature

                # Ensure that VPP was restarted during test.
                # In this case the log should have only more than one notion of
                # vpp start that happened on loading initial configuration:
                #     Aug  2 06:13:03 localhost fwagent: router was started: vpp_pid=...
                #
                lines = agent.grep_log('router was started: vpp_pid=', print_findings=False)
                assert len(lines) > 1, "log has not expected number of VPP starts: %d:%s" % \
                                        (len(lines), '\n'.join(lines))


        ########################################################################
        # Run post test checks
        ########################################################################
        # Ensure that number of VPP starts is same as a number of steps,
        # as every step starts VPP. The step1 starts it on initial configuration,
        # the rest steps restart it on smart sync, as all steps either remove
        # or add interfaces.
        #
        lines = agent.grep_log('router was started: vpp_pid=', print_findings=False)
        assert len(lines) == len(steps), "log has not expected number (%d) of VPP starts: %d:%s" % \
                                (len(steps), len(lines), '\n'.join(lines))

if __name__ == '__main__':
    test()
