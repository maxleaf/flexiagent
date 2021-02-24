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

# Handle device statistics
import fwutils
import time
import loadsimulator
import psutil

from fwtunnel_stats import tunnel_stats_get
import fwglobals
import fwtunnel_stats

# Globals
# Keep updates up to 1 hour ago
UPDATE_LIST_MAX_SIZE = 120

# Keeps the list of last updates
updates_list = []

# Keeps the VPP pids
vpp_pid = ''

# Keeps last stats
stats = {'ok':0, 'running':False, 'last':{}, 'bytes':{}, 'tunnel_stats':{}, 'health':{}, 'period':0}

def update_stats():
    """Update statistics dictionary using values retrieved from VPP interfaces.

    :returns: None.
    """
    global stats
    global vpp_pid

    # If vpp is not running or has crashed (at least one of its process
    # IDs has changed), reset the statistics and update the vpp pids list
    current_vpp_pid = fwutils.vpp_pid()
    if not current_vpp_pid or current_vpp_pid != vpp_pid:
        reset_stats()
        vpp_pid = current_vpp_pid

    if not vpp_pid:
        stats['ok'] = 0
    else:
        new_stats = fwutils.get_vpp_if_count()
        if not new_stats:
            stats['ok'] = 0
        else:
            prev_stats = dict(stats)  # copy of prev stats
            stats['time'] = time.time()
            stats['last'] = new_stats
            stats['ok'] = 1
            # Update info if previous stats valid
            if prev_stats['ok'] == 1:
                if_bytes = {}
                tunnel_stats = tunnel_stats_get()
                fwglobals.g.stun_wrapper.handle_down_tunnels(tunnel_stats)
                for intf, counts in list(stats['last'].items()):
                    if (intf.startswith('gre') or
                        intf.startswith('loop')): continue
                    prev_stats_if = prev_stats['last'].get(intf, None)
                    if prev_stats_if != None:
                        rx_bytes = 1.0 * (counts['rx_bytes'] - prev_stats_if['rx_bytes'])
                        rx_pkts  = 1.0 * (counts['rx_pkts'] - prev_stats_if['rx_pkts'])
                        tx_bytes = 1.0 * (counts['tx_bytes'] - prev_stats_if['tx_bytes'])
                        tx_pkts  = 1.0 * (counts['tx_pkts'] - prev_stats_if['tx_pkts'])
                        calc_stats = {
                                'rx_bytes': rx_bytes,
                                'rx_pkts': rx_pkts,
                                'tx_bytes': tx_bytes,
                                'tx_pkts': tx_pkts
                            }
                        if (intf.startswith('vxlan_tunnel')):
                            vxlan_id = int(intf[12:])
                            tunnel_id = vxlan_id/2
                            t_stats = tunnel_stats.get(tunnel_id)
                            if t_stats:
                                t_stats.update(calc_stats)
                        else:
                            # For other interfaces try to get interface id
                            dev_id = fwutils.vpp_if_name_to_dev_id(intf)
                            if dev_id:
                                if_bytes[dev_id] = calc_stats

                stats['bytes'] = if_bytes
                stats['tunnel_stats'] = tunnel_stats
                stats['period'] = stats['time'] - prev_stats['time']
                stats['running'] = True if fwutils.vpp_does_run() else False

    # Add the update to the list of updates. If the list is full,
    # remove the oldest update before pushing the new one
    if len(updates_list) is UPDATE_LIST_MAX_SIZE:
        updates_list.pop(0)

    updates_list.append({
            'ok': stats['ok'], 
            'running': stats['running'], 
            'stats': stats['bytes'], 
            'period': stats['period'],
            'tunnel_stats': stats['tunnel_stats'],
            'health': get_system_health(),
            'utc': time.time()
        })

def get_system_health():
    # Get CPU info
    try:
        cpu_stats = psutil.cpu_percent(percpu = True)
    except Exception as e:
        fwglobals.log.excep("Error getting cpu stats: %s" % str(e))
        cpu_stats = [0]
    # Get memory info
    try:
        memory_stats = psutil.virtual_memory().percent
    except Exception as e:
        fwglobals.log.excep("Error getting memory stats: %s" % str(e))
        memory_stats = 0
    # Get disk info
    try:
        disk_stats = psutil.disk_usage('/').percent
    except Exception as e:
        fwglobals.log.excep("Error getting disk stats: %s" % str(e))
        disk_stats = 0
    # Get temperature info
    try:
        temp_stats = {'value':0.0, 'high':100.0, 'critical':100.0}
        all_temp = psutil.sensors_temperatures()
        for ttype, templist in list(all_temp.items()):
            for temp in templist:
                if temp.current > temp_stats['value']:
                    temp_stats = {'value':temp.current, 'high':temp.high, 'critical':temp.critical}
    except Exception as e:
        fwglobals.log.excep("Error getting temperature stats: %s" % str(e))

    return {'cpu': cpu_stats, 'mem': memory_stats, 'disk': disk_stats, 'temp': temp_stats}

def get_stats():
    """Return a new statistics dictionary.

    :returns: Statistics dictionary.
    """
    res_update_list = list(updates_list)
    del updates_list[:]

    reconfig = fwutils.get_reconfig_hash()

    # If the list of updates is empty, append a dummy update to
    # set the most up-to-date status of the router. If not, update
    # the last element in the list with the current status of the router
    if loadsimulator.g.enabled():
        status = True
        state = 'running'
        reason = ''
        reconfig = ''
    else:
        status = True if fwutils.vpp_does_run() else False
        (state, reason) = fwutils.get_router_state()
    if not res_update_list:
        res_update_list.append({
            'ok': stats['ok'],
            'running': status,
            'state': state,
            'stateReason': reason,
            'stats': {},
            'tunnel_stats': {},
            'health': {},
            'period': 0,
            'utc': time.time(),
            'reconfig': reconfig
        })
    else:
        res_update_list[-1]['running'] = status
        res_update_list[-1]['state'] = state
        res_update_list[-1]['stateReason'] = reason
        res_update_list[-1]['reconfig'] = reconfig
        res_update_list[-1]['health'] = get_system_health()

    return {'message': res_update_list, 'ok': 1}

def update_state(new_state):
    """Update router state field.

    :param new_state:         New state.

    :returns: None.
    """
    stats['running'] = new_state

def reset_stats():
    """Reset statistics.

    :returns: None.
    """
    global stats
    stats = {'running': False, 'ok':0, 'last':{}, 'bytes':{}, 'tunnel_stats':{}, 'health':{}, 'period':0, 'reconfig':False}