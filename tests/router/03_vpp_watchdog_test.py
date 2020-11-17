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
import sys
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_start_router_add_tunnel_file = os.path.join(cli_path, 'start-router_add-tunnel.cli')
cli_dhcp_on_primary_wan_start_router_add_tunnel_file   = os.path.join(cli_path, 'dhcp-on-primary-wan_start-router.cli')
cli_dhcp_on_secondary_wan_start_router_add_tunnel_file = os.path.join(cli_path, 'dhcp-on-secondary-wan_start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')


def kill_vpp_and_restore(agent, expected_vpp_cfg):

    # Kill vpp and give a watchdog chance to restart it
    vpp_pid_before = fwtests.vpp_pid()
    if not vpp_pid_before:
        return (False, "failed to fetch pid of vpp")

    os.system("sudo kill -9 %s" % vpp_pid_before)
    time.sleep(1)

    # Ensure that watchdog detected vpp crash and restarted it
    started = fwtests.wait_vpp_to_start(timeout=40)
    if not started:
        return (False, "vpp was not re-started")
    vpp_pid_after = fwtests.vpp_pid()
    if vpp_pid_after == vpp_pid_before:
        return (False, "vpp was not re-started probably, same pid: %d" % vpp_pid_after)

    # Ensure that restore finished
    restored = agent.wait_log_line("restore finished", timeout=90)
    if not restored:
        return (False, "'restore finished' line was not found in log")

    # Ensure that configuration was restored
    configured = fwtests.wait_vpp_to_be_configured(expected_vpp_cfg, timeout=30)
    if not configured:
        return (False, "vpp configuration was not restored")

    # Stop router
    (ok, err_str) = agent.cli('-f %s' % cli_stop_router_file)
    if not ok:
        return (False, "failed to stop vpp: %s" % err_str)

    return (True, None)


######################################################################
# This flow checks if the watchdog catchs the crashed vpp,
# than it restarts the vpp and restores the configuration correctly.
######################################################################
def flow_01():
    with fwtests.TestFwagent() as agent:

        expected_vpp_cfg=[('interfaces', 6),('tunnels', 2)]

        (ok, err_str) = agent.cli('-f %s' % cli_start_router_add_tunnel_file,
                                daemon=True, expected_vpp_cfg=expected_vpp_cfg)
        assert ok, err_str

        (ok, err_str) = kill_vpp_and_restore(agent, expected_vpp_cfg)
        assert ok, err_str

######################################################################
# This flow checks if the watchdog catchs the crashed vpp and restores
# it properly, when primary WAN interface is configured with DHCP.
######################################################################
def flow_02(remove_dhcp_ip_before_restore=False):
    with fwtests.TestFwagent() as agent:

        expected_vpp_cfg=[('interfaces', 3),('tunnels', 0)]

        (ok, err_str) = agent.cli('-f %s' % cli_dhcp_on_primary_wan_start_router_add_tunnel_file,
                                daemon=True, expected_vpp_cfg=expected_vpp_cfg, check_log=True)
        assert ok, err_str

        if remove_dhcp_ip_before_restore:
            ret = os.system("dhclient -r")
            assert ret == 0, "'dhclient -r' failed with %d" % ret

        (ok, err_str) = kill_vpp_and_restore(agent, expected_vpp_cfg)
        assert ok, err_str

######################################################################
# This flow checks if the watchdog catchs the crashed vpp and restores
# it properly, when primary WAN interface is configured with DHCP, but
# the interface lost IP (by dhclient -r) before restore.
######################################################################
def flow_03():
    flow_02(remove_dhcp_ip_before_restore=True)

######################################################################
# This flow checks if the watchdog catchs the crashed vpp and restores
# it properly, when secondary WAN interface is configured with DHCP, but
# has IP neither before nor after restore due to disable DHCP server.
######################################################################
def flow_04():
    with fwtests.TestFwagent() as agent:

        expected_vpp_cfg=[('interfaces', 2),('tunnels', 0)]

        (ok, err_str) = agent.cli('-f %s' % cli_dhcp_on_secondary_wan_start_router_add_tunnel_file,
                                daemon=True, expected_vpp_cfg=expected_vpp_cfg, check_log=True)
        assert ok, err_str

        (ok, err_str) = kill_vpp_and_restore(agent, expected_vpp_cfg)
        assert ok, err_str


def test():
    print("")
    print("    flow_01")
    flow_01()
    print("    flow_02")
    flow_02()
    print("    flow_03")
    flow_03()
    print("    flow_04")
    flow_04()


if __name__ == '__main__':
    test()
