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

from fwlog import FwObjectLogger

class FwObject(FwObjectLogger):
    """This is FlexiWAN version of the Python 'object' class.
    It provides functionality which is common for all FlexiWAN objects.
    The main purpose is to provide seamless logging for objects
    by calling self.log(), while still using object specific data like class name.
    """
    def __init__(self):
        FwObjectLogger.__init__(self)

