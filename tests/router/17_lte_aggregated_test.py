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

######################################################################
# This test checks lte system api requests combined with router api
######################################################################

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
            (ok, err_str) = agent.cli('-f %s' % step,
                                    expected_vpp_cfg=expected_vpp_cfg[idx],
                                    expected_router_cfg=expected_dump_cfg[idx])
            assert ok, err_str

            if idx == 0:
                # Ensure system api requests executed before router api
                #
                lines = agent.grep_log('FWROUTER_API|FWSYSTEM_API')
                system_api_index = [i for i, s in enumerate(lines) if 'FWSYSTEM_API' in s][0]
                router_api_index = [i for i, s in enumerate(lines) if 'FWROUTER_API' in s][0]
                assert system_api_index < router_api_index, "System api requests must expected before router api: %s" % '\n'.join(lines)


if __name__ == '__main__':
    test()
