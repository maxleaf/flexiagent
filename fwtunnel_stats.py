#################################################################################
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

import copy
import os
import re
import time
from netaddr import *
import shlex
from subprocess import Popen, PIPE, STDOUT
import threading
import fwglobals
import fwutils

tunnel_stats_global = {}
tunnel_stats_global_lock = threading.RLock()

TIMEOUT = 15
WINDOW_SIZE = 30
APPROX_FACTOR = 16

def tunnel_stats_get_simple_cmd_output(cmd, stderr=STDOUT):
    """Execute a simple external command and get its output.

    :param cmd:         Bash command
    :param stderr:      Where to print errors.

    :returns: Command execution result.
    """
    args = shlex.split(cmd)
    return Popen(args, stdout=PIPE, stderr=stderr).communicate()[0].decode()

def tunnel_stats_get_ping_time(host):
    """Use fping to get RTT.

    :param host:         IP address to ping.

    :returns: RTT value on success and 0 otherwise.
    """
    host = host.split(':')[0]
    cmd = "fping {host} -C 1 -q".format(host=host)
    res = [float(x) for x in tunnel_stats_get_simple_cmd_output(cmd).strip().split(':')[-1].split() if x != '-']
    if len(res) > 0:
        return sum(res) / len(res)
    else:
        return 0

def tunnel_stats_clear():
    """Clear previously collected statistics.

    :returns: None.
    """
    with tunnel_stats_global_lock:
        tunnel_stats_global.clear()

def tunnel_stats_add(tunnel_id, loopback_addr):
    """Add tunnel statistics entry into a dictionary.

    :param tunnel_id:         Tunnel identifier.
    :param loopback_addr:     Loopback local end ip address.

    :returns: None.
    """
    ip_addr = IPNetwork(loopback_addr)
    stats_entry = dict()
    stats_entry['loopback_network'] = str(ip_addr)
    stats_entry['sent'] = 0
    stats_entry['received'] = 0
    stats_entry['drop_rate'] = 0
    stats_entry['rtt'] = 0
    stats_entry['timestamp'] = 0

    for ip in ip_addr:
        if (ip.value != ip_addr.value):
            stats_entry['loopback_remote'] = str(ip)
        else:
            stats_entry['loopback_local'] = str(ip)

    with tunnel_stats_global_lock:
        tunnel_stats_global[tunnel_id] = stats_entry

def tunnel_stats_remove(tunnel_id):
    with tunnel_stats_global_lock:
        del tunnel_stats_global[tunnel_id]

def tunnel_stats_test():
    """Update RTT, drop rate and other fields for all tunnels.

    :returns: None.
    """
    tunnel_stats_global_copy = {}
    with tunnel_stats_global_lock:
        tunnel_stats_global_copy = copy.deepcopy(tunnel_stats_global)

    for key, value in tunnel_stats_global_copy.items():
        value['sent'] += 1

        rtt = tunnel_stats_get_ping_time(value['loopback_remote'])
        if rtt > 0:
            value['received'] += 1
            value['timestamp'] = time.time()

        value['rtt'] = value['rtt'] + (rtt - value['rtt']) / APPROX_FACTOR
        value['drop_rate'] = 100 - value['received'] * 100 / value['sent']

        if (value['sent'] == WINDOW_SIZE):
            value['sent'] = 0
            value['received'] = 0

    with tunnel_stats_global_lock:
        for key in list(tunnel_stats_global.keys()):
            if key in tunnel_stats_global_copy:
                tunnel_stats_global[key] = tunnel_stats_global_copy[key]

def tunnel_stats_get():
    """Return a new tunnel status dictionary.
    Update tunnel status based on timeout.

    :returns: dictionary of tunnel statistics.
    """
    tunnel_stats = {}
    cur_time = time.time()
    tunnel_stats_global_copy = {}

    with tunnel_stats_global_lock:
        tunnel_stats_global_copy = copy.deepcopy(tunnel_stats_global)

    for key, value in tunnel_stats_global_copy.items():
        tunnel_stats[key] = {}
        tunnel_stats[key]['rtt'] = value['rtt']
        tunnel_stats[key]['drop_rate'] = value['drop_rate']

        if ((value['timestamp'] == 0) or (cur_time - value['timestamp'] > TIMEOUT)):
            tunnel_stats[key]['status'] = 'down'
        else:
            tunnel_stats[key]['status'] = 'up'

    return tunnel_stats

def get_if_addr_in_connected_tunnels(tunnel_stats, tunnels):
    """ get set of addresses that are part of any connected tunnels
    : param tunnel_stat : statistics of tunnels.
    : param tunnels     : list of tunnels and their properties
    : return : set of IP addresses part of connected tunnels
    """
    ip_up_set = set()
    if tunnels and tunnel_stats:
        for tunnel in tunnels:
            tunnel_id = tunnel.get('tunnel-id')
            if tunnel_id and tunnel_stats.get(tunnel_id):
                if tunnel_stats[tunnel_id].get('status') == 'up':
                    ip_up_set.add(tunnel['src'])
    return ip_up_set
