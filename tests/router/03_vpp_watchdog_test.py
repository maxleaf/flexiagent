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
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')

######################################################################
# This Test checks if the watchdog catchs the crashed vpp,
# restarts it and restores the configuration correctly.
######################################################################
def test():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_start_router_add_tunnel_file, daemon=True)
        assert ok

        started = fwtests.wait_vpp_to_start(timeout=40)
        assert started

        configured = fwtests.wait_vpp_to_be_configured([('interfaces', 6),('tunnels', 2)], timeout=30)
        assert configured

        # Kill vpp and give a watchdog chance to restart it
        vpp_pid_before = fwtests.vpp_pid()
        assert vpp_pid_before

        os.system("sudo kill -9 %s" % vpp_pid_before)
        time.sleep(1)

        # Ensure that watchdog detected vpp crash and restarted it
        started = fwtests.wait_vpp_to_start(timeout=40)
        assert started
        vpp_pid_after = fwtests.vpp_pid()
        assert vpp_pid_after != vpp_pid_before, "pid before kill %s, pid after kill %s" % (vpp_pid_before, vpp_pid_after)

        # Ensure that restore finished
        restored = agent.wait_log_line("restore finished", timeout=10)
        assert restored

        # Ensure that configuration was restored
        configured = fwtests.wait_vpp_to_be_configured([('interfaces', 6),('tunnels', 2)], timeout=30)
        assert configured

        # Stop router
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok


if __name__ == '__main__':
    test()
