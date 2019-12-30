#! /usr/bin/python

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

import fwglobals

def revert(req_key):
    """Generate revert commands.
    Goes over list of complement command tuples from end to beginning
    and for every command tuple add it's revert command to list.
    In this way we create list of commands that reverts the original request.

     :param req_key:        Command's key to be reverted.

     :returns: A list of commands.
     """
    cmd_list = []
    cmd_list_src = []

    try:
        (cmd_list_src , executed) = fwglobals.g.router_api.db_requests.fetch_cmd_list(req_key)
    except KeyError as e:
        pass

    # If there is no 'add-XXX' commands to revert,
    # or if the 'add-XXX' commands were never executed,
    # return empty list, so nothing will be reverted.
    if len(cmd_list_src) == 0 or executed == False:
        return []

    for cmd_src in reversed(cmd_list_src):
        if 'revert' in cmd_src:
            cmd = {}
            cmd['cmd'] = cmd_src['revert']
            cmd['revert'] = cmd_src['cmd']
            cmd_list.append(cmd)
    return cmd_list
