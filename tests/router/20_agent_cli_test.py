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
sys.path.append(code_root)
import fwtests
import fwutils

cli_path = __file__.replace('.py', '')
cli_add_config_file = os.path.join(cli_path, 'add-config.cli')
cli_remove_config_file = os.path.join(cli_path, 'remove-config.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')

tests = [
    { 'api': 'cmd',     'args': 'reset -q -d',  'vpp_should_run': False, 'database_expected_empty': True },
    { 'api': 'cmd',     'args': 'reset -s',     'vpp_should_run': True,  'database_expected_empty': False },
    { 'api': 'kill',    'args': None,           'vpp_should_run': False, 'database_expected_empty': False },
    { 'api': 'kill',    'args': '--clean_cfg',  'vpp_should_run': False, 'database_expected_empty': True }
]

def test():
    for (idx,test) in enumerate(tests):
        daemon = True if idx == 0 else False
        def call(agent):
            handler_func = getattr(agent, test['api'])
            if test['args']:
                (ok, _) = handler_func(test['args'])
            else:
                (ok, _) = handler_func()
            return (ok, _)

        with fwtests.TestFwagent() as agent:

            # cmd when vpp isn't running
            (ok, _) = call(agent)
            assert ok

            (ok, _) = agent.cli('-f %s' % cli_add_config_file, daemon=daemon)
            assert ok
            (ok, _) = agent.cli('-f %s' % cli_start_router_file)

            # cmd when vpp is running
            (ok, _) = call(agent)
            assert ok

            is_run = fwutils.vpp_does_run()
            assert test['vpp_should_run'] == is_run, \
                'VPP should be %s after %s' % ('run' if test['vpp_should_run'] else 'stopped', test['args'])

            dump_configuration = agent.show("--configuration")
            assert test['database_expected_empty'] == (dump_configuration ==''), \
                'Device DB should be %s after %s' % ('empty' if test['expected_database'] == '' else 'stopped', test['args'])

if __name__ == '__main__':
    test()
