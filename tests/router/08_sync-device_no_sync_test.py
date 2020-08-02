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
cli_start_router_file      = os.path.join(cli_path, 'step1_start_router_with_full_configuration.cli')
cli_expected_cfg_dump_file = os.path.join(cli_path, 'step1_expected_configuration_dump.json')
cli_expected_vpp_cfg_file  = os.path.join(cli_path, 'step1_expected_vpp_configuration.json')

################################################################################
# This test feeds agent with router configuration out of <cli_start_router_file>
# that includes all configuration items like interfaces, tunnels, dhcp-server,
# routes, applications, multilink-policies, etc.
# Than inject the 'sync-device' request with special attribute 'type' it ensures the proper configuration by:
#   1. Fetching configuration items from the running VPP and matching them
#      against expected VPP configuration loaded from <cli_expected_vpp_cfg_file>
#   2. Dumping the agent router configuration database using the
#      "fwagent show --router configuration" command and matching it's output
#      against the expected configuration dump file <cli_expected_cfg_file>
# Than it injects 'get-device-stats' message in order to get the current
# configuration signature.
# Than it injects 'sync-device' message with no configuration but with current
# configuration signature retrieved from reply to the previous 'get-device-stats'
# message.
# At this point no configuration synchronization should happen. This is because
# the 'sync-device' message has same configuration signature as the one that
# exists on device. Ensure this by validating math between VPP configuration and
# configuration database dump and the expected VPP configuration and dump.
################################################################################
def test():
    with fwtests.TestFwagent() as agent:

        # Ensure that the configuration database signature is empty now,
        # as the database was not updated yet after agent reset on test initialization
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        cfg_signature = ret.get('router-cfg-hash')
        assert not cfg_signature, "router-cfg-hash is not empty!\n%s" % json.dumps(ret)

        # Start router with initial configuration
        #
        (ok, _) = agent.cli('-f %s' % cli_start_router_file, daemon=True)
        assert ok

        # Ensure that initial configuration was applied properly
        #
        vpp_configured = fwtests.wait_vpp_to_be_configured(cli_expected_vpp_cfg_file, timeout=30)
        assert vpp_configured
        router_configured = fwtests.router_is_configured(cli_expected_cfg_dump_file, fwagent_py=agent.fwagent_py)
        assert router_configured

        # Ensure that the configuration database signature was updated.
        # As well store the retrieved signature for later usage within
        # 'sync-device' request that should cause no sync.
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        cfg_signature = ret.get('router-cfg-hash')
        assert cfg_signature, "router-cfg-hash is empty!\n%s" % json.dumps(ret)

        # Inject sync-device request with current hash value, so no sync should occur
        #
        msg_sync_device_no_sync = {
                                    "entity": "agent",
                                    "message": "sync-device",
                                    "params": {
                                        "router-cfg-hash": cfg_signature
                                    }
                                  }
        cli_sync_no_sync_file = 'sync-device.cli'
        with open(cli_sync_no_sync_file, 'w') as f:
            json.dump(msg_sync_device_no_sync, f)
        (ok, _) = agent.cli('-f %s' % cli_sync_no_sync_file)
        assert ok, "failed to inject %s: %s" % (cli_sync_no_sync_file, json.dumps(msg_sync_device_no_sync))
        os.remove(cli_sync_no_sync_file)

        # Ensure that initial configuration was not changed
        #
        vpp_configured = fwtests.wait_vpp_to_be_configured(cli_expected_vpp_cfg_file, timeout=30)
        assert vpp_configured
        router_configured = fwtests.router_is_configured(cli_expected_cfg_dump_file, fwagent_py=agent.fwagent_py)
        assert router_configured

        # Ensure no sync is noted in log
        #
        lines = agent.grep_log('no need to sync', print_findings=False)
        assert len(lines) > 0, "log has no mention of 'no-sync'"
        lines = agent.grep_log('smart sync')
        assert len(lines) == 0, "log mentions smart sync: %s" % '\n'.join(lines)
        lines = agent.grep_log('full sync')
        assert len(lines) == 0, "log mentions full sync: %s" % '\n'.join(lines)

        # Ensure no errors in log
        #
        lines = agent.grep_log('error: ')
        assert len(lines) == 0, "errors found in log: %s" % '\n'.join(lines)

        # Ensure that the configuration database signature was reset,
        # even if no real synchronization was conducted. This is what flexiManage
        # expect flexiEdge to do if 'sync-device' is replied with success.
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        cfg_signature = ret.get('router-cfg-hash')
        assert cfg_signature == '', "signature was not reset on 'sync-device' success: %s" % cfg_signature

if __name__ == '__main__':
    test()
