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

# This migration removes NAT section from VPP startup.conf

import os
import re
import yaml
import sys
import subprocess

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwglobals
import fwutils

from fwrouter_cfg import FwRouterCfg
from fwrouter_api import fwrouter_translators
from tools.common.fw_vpp_startupconf import FwStartupConf

VPP_CONFIG_FILE = '/etc/vpp/startup.conf'

def vpp_startup_conf_add_nat(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()
    if config['nat'] == None:
        tup = p.create_element('nat')
        config.append(tup)
        config['nat'].append(p.create_element('endpoint-dependent'))
        config['nat'].append(p.create_element('translation hash buckets 1048576'))
        config['nat'].append(p.create_element('translation hash memory 268435456'))
        config['nat'].append(p.create_element('user hash buckets 1024'))
        config['nat'].append(p.create_element('max translations per user 10000'))

    p.dump(config, vpp_config_filename)

def vpp_startup_conf_remove_nat(vpp_config_filename):
    p = FwStartupConf(vpp_config_filename)
    config = p.get_root_element()
    key = p.get_element(config, 'nat')
    if key:
        p.remove_element(config,key)
    p.dump(config, vpp_config_filename)

def migrate(prev_version, new_version, upgrade):
    try:
        print("* Migrating remove-nat...")

        if upgrade == 'upgrade':
            major_version = int(prev_version.split('-')[0].split('.')[0])
            if major_version < 4:
                vpp_startup_conf_remove_nat(VPP_CONFIG_FILE)

        if upgrade == 'downgrade':
            major_version = int(new_version.split('-')[0].split('.')[0])
            if major_version < 4:
                vpp_startup_conf_add_nat(VPP_CONFIG_FILE)

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()


