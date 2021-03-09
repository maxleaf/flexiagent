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
import time
import pytest

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')

def test():
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.cli' % tests_path))
    for (idx,t) in enumerate(test_cases):
        with fwtests.TestFwagent() as agent:

            if idx == 0:
                print("")
            print("   " + os.path.basename(t))

            (ok,_) = agent.cli('-f %s' % t)
            assert ok, "%s failed" % t

if __name__ == '__main__':

    test()