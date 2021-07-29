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
import subprocess
import time

CODE_ROOT = os.path.realpath(__file__).replace('\\', '/').split('/tests/')[0]
TEST_ROOT = CODE_ROOT + '/tests/'
sys.path.append(CODE_ROOT)
sys.path.append(TEST_ROOT)
import fwutils
import fwtests

cli_path = __file__.replace('.py', '')
cli_add_lte_file = os.path.join(cli_path, 'add-lte.cli')
cli_remove_lte_file = os.path.join(cli_path, 'remove-lte.cli')
cli_add_config_file = os.path.join(cli_path, 'add-config.cli')
cli_remove_config_file = os.path.join(cli_path, 'remove-config.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')

######################################################################
# This test checks watchdog monitoring of lte
######################################################################

def lte_disconnect():
    subprocess.check_call('mbimcli -d /dev/cdc-wdm0 --device-open-proxy --disconnect=0', shell=True)

def test():
    with fwtests.TestFwagent() as agent:
        lines_before = len(agent.grep_log('lte modem is disconnected on', print_findings=False))

        (ok, _) = agent.cli('-f %s' % cli_add_lte_file, daemon=True)
        assert ok

        lte_disconnect()
        time.sleep(12)
        lines = agent.grep_log('lte modem is disconnected on', print_findings=False)
        assert len(lines) > lines_before, "log has no mention of lte modem is disconnected on: %s" % '\n'.join(lines)
        lines_before = len(lines)

        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok

        lte_disconnect()
        time.sleep(12)
        lines = agent.grep_log('lte modem is disconnected on', print_findings=False)
        assert len(lines) > lines_before, "log has no mention of lte modem is disconnected on: %s" % '\n'.join(lines)
        lines_before = len(lines)

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        lte_disconnect()
        time.sleep(12)
        lines = agent.grep_log('lte modem is disconnected on', print_findings=False)
        assert len(lines) > lines_before, "log has no mention of lte modem is disconnected on: %s" % '\n'.join(lines)

        agent.cli('-f %s' % cli_remove_config_file)

        agent.cli('-f %s' % cli_stop_router_file)

        agent.cli('-f %s' % cli_remove_lte_file)


if __name__ == '__main__':
    test()
