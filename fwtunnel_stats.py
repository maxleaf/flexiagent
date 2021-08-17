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

def tunnel_stats_get_ping_time(tunnels):
    """Use fping to get RTT.

    :param tunnels:         IP addresses to ping.

    :returns: RTT values on success and 0 otherwise.
    """
    ret = {}

    # cmd output example: "10.100.0.64  : 2.12 0.51 2.14"
    # 10.100.0.64 - host and calculate avg(2.12, 0.51, 2.14) as rtt
    for tunnel in tunnels:
        interface = tunnel['interface']
        for host in tunnel['hosts']:
            cmd = "fping %s -C 1 -q -I %s" % (host, interface)
            row = tunnel_stats_get_simple_cmd_output(cmd).strip()
            host_rtt = [x.strip() for x in row.strip().split(':')]
            rtt = [float(x) for x in host_rtt[-1].split() if x != '-']
            ret[host_rtt[0]] = sum(rtt) / len(rtt) if len(rtt) > 0 else 0

    return ret

def tunnel_stats_clear():
    """Clear previously collected statistics.

    :returns: None.
    """
    with tunnel_stats_global_lock:
        tunnel_stats_global.clear()

def tunnel_stats_add(tunnel_id, remote_ip, local_sw_if_index):
    """Add tunnel statistics entry into a dictionary.

    :param tunnel_id:         Tunnel identifier.
    :param remote_ip:         Remote end ip address.

    :returns: None.
    """
    stats_entry = dict()
    stats_entry['sent'] = 0
    stats_entry['received'] = 0
    stats_entry['drop_rate'] = 0
    stats_entry['rtt'] = 0
    stats_entry['timestamp'] = 0

    stats_entry['loopback_remote'] = remote_ip
    stats_entry['local_sw_if_index'] = local_sw_if_index

    with tunnel_stats_global_lock:
        tunnel_stats_global[tunnel_id] = stats_entry

def tunnel_stats_remove(tunnel_id):
    with tunnel_stats_global_lock:
        del tunnel_stats_global[tunnel_id]

def tunnel_stats_test():
    """Update RTT, drop rate and other fields for all tunnels.

    :returns: None.
    """
    if not tunnel_stats_global:
        return

    tunnel_stats_global_copy = {}
    with tunnel_stats_global_lock:
        tunnel_stats_global_copy = copy.deepcopy(tunnel_stats_global)

    tunnels = []
    for x in tunnel_stats_global_copy.values():
        hosts = []
        host = x.get('loopback_remote', '').split(':')[0]
        interface = fwutils.vpp_sw_if_index_to_tap(x.get('local_sw_if_index', None))
        hosts.append(host)
        tunnels.append({'interface':interface, 'hosts':hosts})
    tunnel_rtt = tunnel_stats_get_ping_time(tunnels)

    for tunnel_id, stats in tunnel_stats_global_copy.items():
        sw_if_index = stats['local_sw_if_index']
        flags = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump(sw_if_index=sw_if_index)[0].flags
        stats['state'] = flags
        is_up = fwutils.linux_is_interface_up(sw_if_index)
        if is_up and flags == 0 or not is_up and flags != 0:
            fwutils.linux_interface_set_state(sw_if_index, flags)

        stats['sent'] += 1

        rtt = tunnel_rtt.get(stats['loopback_remote'], 0)
        if rtt > 0:
            stats['received'] += 1
            stats['timestamp'] = time.time()

        stats['rtt'] = stats['rtt'] + (rtt - stats['rtt']) / APPROX_FACTOR
        stats['drop_rate'] = 100 - stats['received'] * 100 / stats['sent']

        if (stats['sent'] == WINDOW_SIZE):
            stats['sent'] = 0
            stats['received'] = 0

    with tunnel_stats_global_lock:
        for tunnel_id in list(tunnel_stats_global.keys()):
            if tunnel_id in tunnel_stats_global_copy:
                tunnel_stats_global[tunnel_id] = tunnel_stats_global_copy[tunnel_id]

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

    for tunnel_id, stats in tunnel_stats_global_copy.items():
        tunnel_stats[tunnel_id] = {}
        tunnel_stats[tunnel_id]['rtt'] = stats['rtt']
        tunnel_stats[tunnel_id]['drop_rate'] = stats['drop_rate']

        if ((stats['timestamp'] == 0) or (cur_time - stats['timestamp'] > TIMEOUT)):
            tunnel_stats[tunnel_id]['status'] = 'down'
        else:
            tunnel_stats[tunnel_id]['status'] = 'up'

        if 'state' in stats and stats['state'] == 0:
            tunnel_stats[tunnel_id]['status'] = 'down'

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
