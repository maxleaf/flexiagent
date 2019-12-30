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
cli_add_config_file = os.path.join(cli_path, 'add-config.cli')
cli_remove_config_file = os.path.join(cli_path, 'remove-config.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')

######################################################################
# This flow checks if the configured parameters persist 'stop-router':
# - add-config
# - start-router
# - ensure vpp is configured
# - stop-router
# - ensure vpp doesn't run
# - start-router
# - ensure vpp is configured
######################################################################
def flow_01():
    with fwtests.TestFwagent() as agent:
	
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        assert fwtests.vpp_is_configured([('interfaces', 4),('tunnels', 1)])

        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok

        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        assert fwtests.vpp_is_configured([('interfaces', 4),('tunnels', 1)])

        agent.cli('-f %s' % cli_stop_router_file)

######################################################################
# This flow checks if the removed configured parameters persist 'stop-router':
# - add-config
# - start-router
# - remove-config
# - stop-router
# - start-router
# - ensure vpp is not configured
######################################################################
def flow_02():
    with fwtests.TestFwagent() as agent:
	
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_remove_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 0),('tunnels', 0)])


######################################################################
# This flow checks if the removed configured parameters persist 'stop-router':
# - add-config
# - start-router
# - stop-router
# - remove-config
# - start-router
# - ensure vpp is not configured
######################################################################
def flow_03():
    with fwtests.TestFwagent() as agent:
	
        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_remove_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        assert fwtests.vpp_is_configured([('interfaces', 0),('tunnels', 0)])

def test():
    print("    flow_01")
    flow_01()
    print("    flow_02")
    flow_02()
    print("    flow_03")
    flow_03()

if __name__ == '__main__':
    test()
