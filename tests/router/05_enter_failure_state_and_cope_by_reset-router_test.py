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
import subprocess
import sys
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_fail_router_file   = os.path.join(cli_path, 'fail_router.cli')
cli_stop_router_file   = os.path.join(cli_path, 'stop-router.cli')
cli_add_interface_file = os.path.join(cli_path, 'add-interface.cli')
cli_reset_router_file  = os.path.join(cli_path, 'reset-router.cli')
cli_start_router_file  = os.path.join(cli_path, 'start-router.cli')

######################################################################
# This Test:
# 1. Causes router failure
# 2. Ensures that the failure state is recorded into file
# 3. Ensures that router rejects configuration requests in failure state
# 4. Resets the router state
# 5. Ensures that configuration requests are handled OK now
#
# The failure state is achieved by feeding agent with bad interfaces,
# when vpp is not started yet, than sending it 'start-router' request. 
# ######################################################################
def test():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_fail_router_file)
        assert not ok

        # Ensure that the failure state was recorded into file
        state_file = "/etc/flexiwan/agent/.router.state"
        exists = fwtests.file_exists(state_file)
        assert exists, "%s: file not found/empty file - failure was not recorded" % state_file

        # Ensure that vpp was stopped as a result of failure
        vpp_pid = fwtests.vpp_pid()
        assert vpp_pid is None, "vpp runs (pid=%s)! It should be stopped on failure" % vpp_pid

        # Ensure that configuration requests are not rejected when router is in failed state.
        # Note configuration requests are not blocked to enable management
        # to fix configuration issue that caused failure
        (ok, _) = agent.cli('-f %s' % cli_add_interface_file)
        assert ok, "'add-interface' request was rejected, when router is in failure state"

        # Reset the failure state
        (ok, _) = agent.cli('-f %s' % cli_reset_router_file)
        assert ok, "'reset-router' request failed"

        # Ensure that 'reset-router' deleted failure state record file and emptied request database file
        exists = fwtests.file_exists(state_file)
        assert exists==False, "failure state file still exists: %s" % state_file

        config = agent.show("--configuration router")
        assert config == '', "request database was not emptired by 'reset-router' request:\n%s" % config

        # As request database was emptied, add interface again to check normal activity
        (ok, _) = agent.cli('-f %s' % cli_add_interface_file)
        assert ok

        # Start router and ensure that configuration was applied successfully
        (ok, err_str) = agent.cli('-f %s' % cli_start_router_file,
                                  expected_vpp_cfg=[('interfaces', 1),('tunnels', 0)])
        assert ok, err_str

        # Stop router
        (ok, err_str) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok, err_str

if __name__ == '__main__':
    test()
