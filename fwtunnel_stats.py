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

import os
import re
import time
from netaddr import *
import shlex
from subprocess import Popen, PIPE, STDOUT
import fwglobals
import fwutils

tunnel_stats_global = {}

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
    return Popen(args, stdout=PIPE, stderr=stderr).communicate()[0]

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
    tunnel_stats_global.clear()

def tunnel_stats_add(tunnel_id, loopback_addr):
    """Add tunnel statistics entry into a dictionary.

    :param tunnel_id:         Tunnel identifier.
    :param loopback_addr:     Loopback local end ip address.

    :returns: None.
    """
    ip_addr = IPNetwork(loopback_addr)
    tunnel_stats_global[tunnel_id] = dict()
    tunnel_stats_global[tunnel_id]['loopback_network'] = str(ip_addr)
    tunnel_stats_global[tunnel_id]['sent'] = 0
    tunnel_stats_global[tunnel_id]['received'] = 0
    tunnel_stats_global[tunnel_id]['drop_rate'] = 0
    tunnel_stats_global[tunnel_id]['rtt'] = 0
    tunnel_stats_global[tunnel_id]['timestamp'] = 0

    for ip in ip_addr:
        if (ip.value != ip_addr.value):
            tunnel_stats_global[tunnel_id]['loopback_remote'] = str(ip)
        else:
            tunnel_stats_global[tunnel_id]['loopback_local'] = str(ip)

def tunnel_stats_test():
    """Update RTT, drop rate and other fields for all tunnels.

    :returns: None.
    """
    for value in tunnel_stats_global.values():
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

def tunnel_stats_get():
    """Return a new tunnel status dictionary.
    Update tunnel status based on timeout.

    :returns: dictionary of tunnel statistics.
    """
    tunnel_stats = {}
    cur_time = time.time()

    for key, value in tunnel_stats_global.items():
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

def add_address_of_down_tunnels_to_stun(tunnel_stats, tunnels):
    """ Run over all tunnels and get the source IP address of the tunnels that are not connected.
    If it was disconnected due to changes in its source IP address, check if this IP address is still
    valid. If it is, check that it is not used in other connected tunnels. If it is not used but still
    valid, add it to the STUN cache. It it is in use, do not add it to the STUN cache, because we don't
    want to start sending STUN requests on its behalf as it will lead to disconnection of the other
    tunnels with that IP address.

    : param tunnel_stats : dictionary of tunnel statistics. One of its properties is the tunnel status
                           ("up" or "down")
    : param tunnels      : list of tunnels and their properties
    """
    if not tunnel_stats or not tunnels:
        return
    # Get list if IP addresses used by tunnels
    ip_up_set = get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
    # Get list of all IP addresses in the system
    ip_addr_list = fwutils.get_interface_address_all(filtr = 'gw')
    for tunnel in tunnels:
        key = tunnel['tunnel-id']
        stats = tunnel_stats.get(key)
        if stats:
            status = stats.get('status')
            if status == 'down':
                # Down tunnel found. However, the tunnel might be disconnected due to changes in
                # source IP address. In that case, the current source address of the tunnel
                # is no longer valid. To make things safe, we check if the IP address exists
                # in the system. If it is not, no point on adding it to the STUN cache.
                if tunnel['src'] not in ip_addr_list:
                    fwglobals.log.debug("Tunnel-id %d is down, but its source address %s no longer valid"\
                        %(key, tunnel['src']))
                    continue
                # If valid IP, check if the IP is part of other connected tunnels. If so,
                # do not add it to the STUN hash, as it might cause other connected tunnels
                # with that IP to disconnect. If it is not part of any connected tunnel,
                # add its source IP address to the cache of addresses for which
                # we will send STUN requests.
                if tunnel['src'] not in ip_up_set:
                    fwglobals.log.debug("Tunnel-id %d is down, adding address %s to STUN interfaces cache"\
                        %(key, tunnel['src']))
                    fwglobals.g.stun_wrapper.add_addr(tunnel['src'], True)
                continue
