#! /usr/bin/python3

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

def revert(request, db):
    """Generate list of commands for the 'remove-X' type of requests.
    To do that it fetches the list of commands for the corresponding 'add-X'
    request, goes over this list from the end to the beginning and for every
    command takes it's revert section and adds it to the result list.
    In this way we create list of commands that reverts the original request.

    :param request: The request received from flexiManage.

    :returns: A list of commands.
    """

    # Fetch list of commands for the correspondent 'add-X' request
    (cmd_list_src, executed) = db.get_request_cmd_list(request)

    # If there is no 'add-XXX' commands to revert,
    # or if the 'add-XXX' commands were never executed,
    # return empty list, so nothing will be reverted.
    if not cmd_list_src or executed == False:
        return []

    # Now go and generate list of commands for 'remove-X' request out of the list
    # of commands for the correspondent 'add-X' request.
    cmd_list = []
    for cmd_src in reversed(cmd_list_src):
        if 'revert' in cmd_src:
            cmd = {}
            cmd['cmd'] = cmd_src['revert']
            cmd['revert'] = cmd_src['cmd']
            cmd_list.append(cmd)
    return cmd_list
