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
fping_processes = {}

TIMEOUT = 15
WINDOW_SIZE = 30
APPROX_FACTOR = 16

def start_fping_process(cmd):
    """Execute a simple external command and get its output.

    :param cmd:         Bash command

    :returns: Command execution result.
    """
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
    return process

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
        tunnel_id = tunnel['tunnel_id']
        hosts =  tunnel['hosts']
        rows = None

        cmd = "fping {hosts} -C 1 -q".format(hosts=" ".join(hosts))
        cmd += " -I %s" % interface
        if tunnel_id in fping_processes:
            if fping_processes[tunnel_id].poll() is not None:
                (output, errors) = fping_processes[tunnel_id].communicate()
                rows = errors.strip().splitlines()
                fping_processes[tunnel_id] = start_fping_process(cmd)
        else:
            fping_processes[tunnel_id] = start_fping_process(cmd)

        if rows:
            rtts = []
            for row in rows:
                host_rtt = [x.strip() for x in row.strip().split(':')]
                rtt = host_rtt[1] if host_rtt[1] != '-' else '0'
                rtts.append(float(rtt))
            ret[tunnel_id] = sum(rtts) / len(rtts) if len(rtts) > 0 else 0
        else:
            ret[tunnel_id] = None

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
    for tunnel_id, tunnel_stats_entry in tunnel_stats_global_copy.items():
        hosts = tunnel_stats_entry.get('loopback_remote', [])
        interface = fwutils.vpp_sw_if_index_to_tap(tunnel_stats_entry.get('local_sw_if_index', None))
        tunnels.append({'tunnel_id':tunnel_id, 'interface':interface, 'hosts':hosts})
    tunnel_rtt = tunnel_stats_get_ping_time(tunnels)

    for tunnel_id, stats in tunnel_stats_global_copy.items():
        sw_if_index = stats['local_sw_if_index']
        stats['state'] = fwutils.vpp_get_interface_state(sw_if_index)
        is_up = fwutils.linux_is_interface_up(sw_if_index)
        if is_up and stats['state'] == 0 or not is_up and stats['state'] != 0:
            fwutils.linux_interface_set_state(sw_if_index, stats['state'])

        stats['sent'] += 1

        rtt = tunnel_rtt.get(tunnel_id, 0)
        if rtt is None:
            continue

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

def get_tunnel_info():
    """ get set of remote loopback addresses
    : return : set of remote loopback IP addresses
    """
    tunnel_stats     = tunnel_stats_get()
    tunnels          = fwglobals.g.router_cfg.get_tunnels()
    remote_loopbacks = dict()

    if tunnels and tunnel_stats:
        for tunnel in tunnels:
            tunnel_id = tunnel.get('tunnel-id')
            if 'peer' in tunnel:
                continue
            if tunnel_id and tunnel_stats.get(tunnel_id):
                remote_loop = IPNetwork(tunnel['loopback-iface']['addr'])
                remote_loop.value ^= IPAddress('0.0.0.1').value
                status = tunnel_stats[tunnel_id].get('status')
                remote_loopbacks[str(remote_loop.ip)] = status
    return remote_loopbacks
