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
# This test checks if vpp and linux configured properly
######################################################################

def test():
    with fwtests.TestFwagent() as agent:

        start_interfaces_count = fwtests.linux_interfaces_count()

        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok

        assert fwtests.linux_interfaces_are_configured(start_interfaces_count)

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        assert fwtests.vpp_is_configured([('interfaces', 1),('tunnels', 0)])

        assert fwtests.linux_interfaces_are_configured(start_interfaces_count + 2)

        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok

        assert fwtests.linux_interfaces_are_configured(start_interfaces_count)

        assert not fwtests.vpp_does_run()    # Ensure vpp doesn't run

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        assert fwtests.vpp_is_configured([('interfaces', 1),('tunnels', 0)])

        assert fwtests.linux_interfaces_are_configured(start_interfaces_count + 2)

        agent.cli('-f %s' % cli_stop_router_file)

        assert fwtests.linux_interfaces_are_configured(start_interfaces_count)


if __name__ == '__main__':
    test()
