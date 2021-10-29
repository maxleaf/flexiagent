################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

import enum
import socket
import fwglobals
import fwtunnel_stats
import fwutils
import pyroute2
import subprocess

from pyroute2 import IPDB

ipdb = IPDB()

class FwRouteProto(enum.Enum):
   BOOT = 3
   STATIC = 4
   DHCP = 16

class FwRouteKey:
    """Class used as a route key."""
    def __init__(self, metric, addr, via):
        self.addr       = addr
        self.via        = via
        self.metric     = metric

class FwRouteNextHop:
    """Class used as a route nexthop."""
    def __init__(self, via, dev):
        self.dev        = dev
        self.via        = via

class FwRouteData:
    """Class used as a route data."""
    def __init__(self, prefix, via, dev, proto, metric):
        self.prefix     = prefix
        self.via        = via
        self.dev        = dev
        self.proto      = proto
        self.metric     = metric
        self.dev_id     = fwutils.get_interface_dev_id(dev)
        self.probes     = [True] * fwglobals.g.WAN_FAILOVER_WND_SIZE    # List of ping results
        self.ok         = True      # If True there is connectivity to internet
        self.default    = False     # If True the route is the default one - has lowest metric

    def __str__(self):
        route = '%s via %s dev %s(%s)' % (self.prefix, self.via, self.dev, self.dev_id)
        if self.proto:
            route += (' proto ' + str(self.proto))
        if self.metric:
            route += (' metric ' + str(self.metric))
        return route

class FwLinuxRoutes(dict):
    """The object that represents routing rules found in OS.
    """
    def __init__(self, prefix=None, preference=None, via=None, proto=None):
        self._linux_get_routes(prefix, preference, via, proto)

    def __getitem__(self, item):
        return self[item]

    def _linux_get_routes(self, prefix=None, preference=None, via=None, proto=None):
        preference = int(preference) if preference else 0

        if not proto:
            proto_id = None
        elif proto == 'dhcp':
            proto_id = FwRouteProto.DHCP.value
        elif proto == 'static':
            proto_id = FwRouteProto.STATIC.value
        else:
            fwglobals.log.debug("_linux_get_routes: proto %s is not supported" % proto)
            return

        with pyroute2.IPRoute() as ipr:
            routes = ipr.get_routes(family=socket.AF_INET, proto=proto_id)

            for route in routes:
                nexthops = []
                dst = None # Default routes have no RTA_DST
                metric = 0
                gw = None

                if route['proto'] == FwRouteProto.DHCP.value:
                    proto = 'dhcp'
                elif route['proto'] == FwRouteProto.STATIC.value:
                    proto = 'static'
                else:
                    proto = 'unsupported'

                for attr in route['attrs']:
                    if attr[0] == 'RTA_PRIORITY':
                        metric = int(attr[1])
                    if attr[0] == 'RTA_OIF':
                        dev = ipdb.interfaces[attr[1]].ifname
                    if attr[0] == 'RTA_DST':
                        dst = attr[1]
                    if attr[0] == 'RTA_GATEWAY':
                        gw = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            dev = ipdb.interfaces[elem['oif']].ifname
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    nexthops.append(FwRouteNextHop(attr2[1],dev))
                if not dst: # Default routes have no RTA_DST
                    dst = "0.0.0.0"
                addr = "%s/%u" % (dst, route['dst_len'])

                if gw:
                    nexthops.append(FwRouteNextHop(gw,dev))

                if preference and metric != preference:
                    continue

                if prefix and addr != prefix:
                    continue

                for nexthop in nexthops:
                    if via and via != nexthop.via:
                        continue
                    self[FwRouteKey(metric, addr, nexthop.via)] = FwRouteData(addr, nexthop.via, nexthop.dev, proto, metric)

    def exist(self, addr, metric, via):
        metric = int(metric) if metric else 0
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return True

        # Check if this route exist but with metric changed by WAN_MONITOR
        #
        metric = metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return True

        return False

def add_remove_route(addr, via, metric, remove, dev_id=None, proto='static', dev=None, netplan_apply=True):
    """Add/Remove route.

    :param addr:            Destination network.
    :param via:             Gateway address.
    :param metric:          Metric.
    :param remove:          True to remove route.
    :param dev_id:          Bus address of device to be used for outgoing packets.
    :param proto:           Route protocol.

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    metric = int(metric) if metric else 0

    if addr == 'default':
        return (True, None)

    if not fwutils.linux_check_gateway_exist(via):
        return (True, None)

    if not remove:
        tunnel_addresses = fwtunnel_stats.get_tunnel_info()
        if via in tunnel_addresses and tunnel_addresses[via] != 'up':
            return (True, None)

    routes_linux = FwLinuxRoutes(prefix=addr, preference=metric, proto=proto)
    nexthop = FwLinuxRoutes(prefix=addr, preference=metric,via=via, proto=proto)
    exist_in_linux = True if len(nexthop) >= 1 else False

    if remove and not exist_in_linux:
        return (True, None)

    if not remove and exist_in_linux:
        return (True, None)

    next_hops = ''
    if routes_linux:
        for key in routes_linux.keys():
            if remove and via == key.via:
                continue
            next_hops += ' nexthop via ' + key.via

    metric = ' metric %s' % metric if metric else ' metric 0'
    op     = 'replace'

    if remove:
        if not next_hops:
            op = 'del'
        cmd = "sudo ip route %s %s%s proto %s %s" % (op, addr, metric, proto, next_hops)
    else:
        if via in next_hops:
            return (False, "via in next_hop")
        if not dev_id and not dev:
            cmd = "sudo ip route %s %s%s proto %s nexthop via %s %s" % (op, addr, metric, proto, via, next_hops)
        else:
            if not dev:
                dev = fwutils.dev_id_to_linux_if_name(dev_id)
            if not dev:
                return (False, f"add_remove_route: {str(dev)}/{str(dev_id)} interface was not found")
            cmd = "sudo ip route %s %s%s proto %s nexthop via %s dev %s %s" % (op, addr, metric, proto, via, dev, next_hops)

    try:
        fwglobals.log.debug(cmd)
        output = subprocess.check_output(cmd, shell=True).decode()
    except Exception as e:
        if op == 'del':
            fwglobals.log.debug("'%s' failed: %s, ignore this error" % (cmd, str(e)))
            return (True, None)
        return (False, "Exception: %s\nOutput: %s" % (str(e), output))

    # We need to re-apply Netplan configuration here to install default route that
    # could be removed in the flow before.
    # This will happen if static default route installed by user is exactly the same like
    # default route generated based on interface configuration inside Netplan file.
    if remove and netplan_apply:
        fwutils.netplan_apply("add_remove_route")

    return (True, None)

def check_reinstall_static_routes():
    routes_db = fwglobals.g.router_cfg.get_routes()
    routes_linux = FwLinuxRoutes(proto='static')
    tunnel_addresses = fwtunnel_stats.get_tunnel_info()

    for route in routes_db:
        addr = route['addr']
        via = route['via']
        metric = str(route.get('metric', '0'))
        dev = route.get('dev_id')
        exist_in_linux = routes_linux.exist(addr, metric, via)

        if tunnel_addresses.get(via) == 'down':
            if exist_in_linux:
                add_remove_route(addr, via, metric, True, dev)
            continue

        if not exist_in_linux:
            add_remove_route(addr, via, metric, False, dev)

def add_remove_static_routes(via, is_add):
    routes_db = fwglobals.g.router_cfg.get_routes()

    for route in routes_db:
        if route['via'] != via:
            continue

        addr = route['addr']
        metric = str(route.get('metric', '0'))
        dev = route.get('dev_id')
        via = route['via']

        add_remove_route(addr, via, metric, not is_add, dev)


def update_route_metric(route, new_metric, netplan_apply=False):
    """Updates metric of the specific route in Linux.

    :param route:           The FwRouteData object that reflects route rule in kernel
    :param new_metric:      The new metric to be set for the route.
    :param netplan_apply:   If True the 'netplan apply' command will be run after
                            the update. Take a caution: netplan apply might cancel
                            the metric update by restoring original configuration!

    :returns: True on success, False on failure.
    """
    success, err_str = add_remove_route(route.prefix, route.via, route.metric, True, dev=route.dev, proto=route.proto, netplan_apply=netplan_apply)
    if not success:
        fwglobals.log.error(f"update_route_metric({str(route)}): failed to remove route: {err_str}")
        return False
    success, err_str = add_remove_route(route.prefix, route.via, new_metric, False, dev=route.dev, proto=route.proto, netplan_apply=netplan_apply)
    if not success:
        fwglobals.log.error(f"update_route_metric({str(route)}): failed to add route with new metric: {err_str}")
        return False
    return True
