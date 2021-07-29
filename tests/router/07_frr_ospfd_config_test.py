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
# that /etc/frr/ospfd.conf file is updates properly on interface
# adding, removing and router start and stop cycles.
######################################################################

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_add_config_file = os.path.join(cli_path, 'add-config.cli')
cli_add_config_remove_config_file = os.path.join(cli_path, 'add-remove-config.cli')
cli_start_router_file = os.path.join(cli_path, 'start-router.cli')
cli_stop_router_file = os.path.join(cli_path, 'stop-router.cli')
cli_start_add_config_remove_config_stop_file = os.path.join(cli_path, 'start-router_add-config_remove-config_stop-router.cli')
cli_add_config_start_stop_remove_config_file = os.path.join(cli_path, 'add-config_start-router_stop-router_remove-config.cli')

ospfd_conf_filename = '/etc/frr/ospfd.conf'

def read_ospfd_conf():
    content = ''
    with open(ospfd_conf_filename, 'r') as f:
        content = ''.join(list(filter(lambda line: not line.startswith('!'), f)))
    return content

######################################################################
# This flow checks if every subsequent 'start-router' doesn't blow
# the ospfd.conf with same interfaces:
# - add-config
# - start-router
# - save ospfd.conf
# - stop-router
# - start-router
# - stop-router
# - ensure that current ospfd.conf is equal to the saved previously one
######################################################################
def flow_01():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_add_config_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        ospfd_content_old = read_ospfd_conf()

        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok
        (ok, _) = agent.cli('-f %s' % cli_stop_router_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

######################################################################
# This flow ensures that when all LAN interfaces are removed,
# the ospfd.conf is deleted.
# - start-router
# - save ospfd.conf
# - start-router
# - add-config
# - remove-config
# - stop-router
# - ensure that current ospfd.conf is equal to the saved previously one
# - add-config
# - remove-config
# - ensure that current ospfd.conf is equal to the saved previously one
######################################################################
def flow_02():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        ospfd_content_old = read_ospfd_conf()

        (ok, _) = agent.cli('-f %s' % cli_start_add_config_remove_config_stop_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

        (ok, _) = agent.cli('-f %s' % cli_add_config_remove_config_file)
        assert ok

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

######################################################################
# This flow checks if 'remove-cfg' performed after router was stopped
# takes the ospfd.conf back to the same content that it had before 'add-cfg',
# when router was started.
# Note we make one add-config & start-router & stop-router & remove-config cycle
# to create empty ospfd.conf, as it might not exist at the moment
# of test invocation.
# - start-router
# - save ospfd.conf
# - start-router
# - add-config
# - remove-config
# - stop-router
# - ensure that current ospfd.conf is equal to the saved previously one
# - start-router
# - add-config
# - remove-config
# - stop-router
# - ensure that current ospfd.conf is equal to the saved previously one
######################################################################
def flow_03():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        ospfd_content_old = read_ospfd_conf()

        (ok, _) = agent.cli('-f %s' % cli_start_add_config_remove_config_stop_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

        (ok, _) = agent.cli('-f %s' % cli_start_add_config_remove_config_stop_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

######################################################################
# This flow checks if 'remove-cfg' performed before router was stopped
# takes the ospfd.conf back to the same content that it had before 'add-cfg',
# when router was started.
# Note we make one add-config & start-router & stop-router & remove-config cycle
# to create empty ospfd.conf, as it might not exist at the moment
# of test invocation.
# - start-router
# - save ospfd.conf
# - add-config
# - start-router
# - stop-router
# - remove-config
# - ensure that current ospfd.conf is equal to the saved previously one
# - add-config
# - start-router
# - remove-config
# - stop-router
# - ensure that current ospfd.conf is equal to the saved previously one
######################################################################
def flow_04():
    with fwtests.TestFwagent() as agent:

        (ok, _) = agent.cli('-f %s' % cli_start_router_file)
        assert ok

        ospfd_content_old = read_ospfd_conf()

        (ok, _) = agent.cli('-f %s' % cli_add_config_start_stop_remove_config_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)

        (ok, _) = agent.cli('-f %s' % cli_add_config_start_stop_remove_config_file)
        assert ok

        ospfd_content_new = read_ospfd_conf()

        assert ospfd_content_old == ospfd_content_new, \
              "%s BEFORE test:%s\n\n%s AFTER test:%s\n" % \
              (ospfd_conf_filename, ospfd_content_old, ospfd_conf_filename, ospfd_content_new)


def test():
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
