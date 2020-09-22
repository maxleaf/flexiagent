#################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020 flexiWAN Ltd.
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

import fwglobals

class fwlinuxIfs:

def __init__(self):
    fwglobals.g.AGENT_CACHE['linux_ifs'] = {}
    self.local_cache = fwglobals.g.AGENT_CACHE['linux_ifs']
    self.local_db = SqliteDict(fwglobals.g.ROUTER_CFG_FILE, autocommit=True)

def get_linux_interfaces(self):
    