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

######################################################################
# This test runs a number of flows in order to checks,
# if the configured parameters or absence of configuration
# persist 'stop-router'.
######################################################################

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_before_sync_file      = os.path.join(cli_path, 'step1_cfg_interfaces_tunnels_routes_applications_multilink-policies_dhcp-server.cli')
cli_sync_file             = os.path.join(cli_path, 'step2_cfg_sync-device.cli')
cli_get_device_stats_file = os.path.join(cli_path, 'get_device_stats.cli')
cli_sync_no_sync_file     = os.path.join(cli_path, 'sync-device_no_sync.cli')

dump_before_sync_file = os.path.join(cli_path, 'step1_dump_of_expected_router_configuration.txt')
dump_after_sync_file  = os.path.join(cli_path, 'step2_dump_of_expected_router_configuration.txt')

######################################################################
# This flow feeds agent with router configuration out of
# step1_cfg_interfaces_tunnels_routes_applications_multilink-policies_dhcp-server.cli
# file, ensures that the dump by 'fwagent show --router configuration' matches
# the expected dump stored in 'step1_dump_of_expected_router_configuration.txt'.
# Than it modifies router configuration using the sync-device message stored
# in 'step2_cfg_sync-device.cli' and again ensures that dump matches the expected
# dump. In addition ensure that number of configured interfaces, routes, tunnels,
# etc. matches the configuration provided in sync-device.cli.
######################################################################
def test():
    with fwtests.TestFwagent() as agent:

        fwagent_run_time = 100

        # Ensure that the configuration database signature is empty now,
        # as the database was not updated yet after agent reset on test initialization
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        cfg_signature = ret.get('router-cfg-hash')
        assert not cfg_signature, "router-cfg-hash is not empty!\n%s" % json.dumps(ret)

        # Start router with initial configuration
        #
        (ok, _) = agent.cli('-f %s' % cli_before_sync_file, daemon=True)
        assert ok

        # Ensure that initial configuration was applied properly
        #
        vpp_configured_initial = fwtests.wait_vpp_to_be_configured(
                                            [
                                                ('interfaces', 8),
                                                ('tunnels', 3),
                                                ('dhcp-servers', 1)
                                            ],
                                            timeout=30)
        assert vpp_configured_initial
        router_configured_initial = fwtests.router_is_configured(dump_before_sync_file, fwagent_py=agent.fwagent_py)
        assert router_configured_initial

        # Ensure that the configuration database signature was updated
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
                                        "type": "full-sync",
                                        "router-cfg-hash": cfg_signature
                                    }
                                  }
        with open(cli_sync_no_sync_file, 'w') as f:
            json.dump(msg_sync_device_no_sync, f)
        (ok, _) = agent.cli('-f %s' % cli_sync_no_sync_file)
        assert ok, "failed to inject %s: %s" % (cli_sync_no_sync_file, json.dumps(msg_sync_device_no_sync))
        os.remove(cli_sync_no_sync_file)

        # Ensure that initial configuration was not changed
        #
        vpp_configured_no_sync = fwtests.wait_vpp_to_be_configured(
                                            [
                                                ('interfaces', 8),
                                                ('tunnels', 3),
                                                ('dhcp-servers', 1)
                                            ],
                                            timeout=30)
        assert vpp_configured_no_sync
        router_configured_no_sync = fwtests.router_is_configured(dump_before_sync_file, fwagent_py=agent.fwagent_py)
        assert router_configured_no_sync

        # Inject sync-device request with new configuration
        #
        (ok, _) = agent.cli('-f %s' % cli_sync_file)
        assert ok

        # Ensure that new configuration was applied properly
        #
        vpp_configured_synced = fwtests.wait_vpp_to_be_configured(
                                            [
                                                ('interfaces', 9),
                                                ('tunnels', 3),
                                                ('dhcp-servers', 1)
                                            ],
                                            timeout=40)
        assert vpp_configured_synced
        router_configured_synced = fwtests.router_is_configured(dump_after_sync_file, fwagent_py=agent.fwagent_py)
        assert router_configured_synced

        lines = agent.grep_log('error: ')
        assert len(lines) == 0, "errors found in log!"

        # Ensure that the configuration database signature was reset on
        # synchronization success.
        #
        (ok, ret) = agent.cli('-f %s' % cli_get_device_stats_file)
        cfg_signature = ret.get('router-cfg-hash')
        assert not cfg_signature, "router-cfg-hash is not empty after sync!\n%s" % json.dumps(ret)

        # Clean up - wait until background fwagent exits
        exited = fwtests.wait_fwagent_exit(timeout=fwagent_run_time)
        assert exited

if __name__ == '__main__':
    test()
