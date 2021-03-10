#! /bin/bash

# flexiWAN SD-WAN software - flexiEdge, flexiManage. For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <script_name>"
    exit 2
fi

SCRIPT_PATH=$1

/sbin/modprobe uio_pci_generic

ip link set dev enp0s3 down
ip link set dev enp0s8 down

fwagent cli -f $SCRIPT_PATH

