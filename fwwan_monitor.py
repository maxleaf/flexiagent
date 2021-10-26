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

import re
import subprocess
import sys
import threading
import time
import traceback

import fwglobals
import fwnetplan
import fwroutes
import fwutils

from fwobject import FwObject

class FwWanMonitor(FwObject):
    """This object monitors internet connectivity over default WAN interface,
    and if bad connectivity is detected, it updates routing table to use
    other WAN interface with lowest metric. Than the 'bad' interface is monitored
    to detect the connectivity restore. When it is detected, the routing table
    is updated back with original default route rule.
        To monitor internet connectivity we just ping 1.1.1.1 and 8.8.8.8.
        To get 'bad' default route out of service we increase it's metric to
    be (2.000.000.000 + original metric), so it is still can be used for pings.
    The 2.000.000.000 threshold is derived as a 1/2 of the max u32 value,
    supported by Linux for metrics.
    """
    def __init__(self, standalone):
        """Constructor.

        :param standalone: if True, the module does nothing. It is used for tests.
                        The 'standalone' stands for the agent mode and means,
                        that the agent is not connected to internet.
        """
        self.standalone = standalone
        if self.standalone:
            return

        FwObject.__init__(self)

        # Make few shortcuts to get more readable code
        #
        self.SERVERS         = fwglobals.g.WAN_FAILOVER_SERVERS
        self.WND_SIZE        = fwglobals.g.WAN_FAILOVER_WND_SIZE
        self.THRESHOLD       = fwglobals.g.WAN_FAILOVER_THRESHOLD
        self.WATERMARK       = fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK

        self.num_servers     = len(self.SERVERS)
        self.current_server  = self.num_servers - 1  # The first selection will take #0
        self.routes          = fwglobals.g.cache.wan_monitor['enabled_routes']
        self.disabled_routes = fwglobals.g.cache.wan_monitor['disabled_routes']
        self.route_rule_re   = re.compile(r"(\w+) via ([0-9.]+) dev (\w+)(.*)") #  'default via 20.20.20.22 dev enp0s9 proto dhcp metric 100'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        if self.standalone:
            return
        self.thread_wan_monitor = threading.Thread(target=self.main_loop, name="FwWanMonitor")
        self.thread_wan_monitor.start()

    def finalize(self):
        """Destructor method
        """
        if self.standalone:
            return
        if self.thread_wan_monitor:
            self.thread_wan_monitor.join()
            self.thread_wan_monitor = None


    def main_loop(self):
        self.log.debug("loop started")

        prev_time = time.time()

        while not fwglobals.g.teardown:

            try: # Ensure thread doesn't exit on exception

                while fwglobals.g.router_api.state_is_starting_stopping():
                    self.log.debug("vpp is being started/stopped")
                    time.sleep(5)

                server = self._get_server()
                routes = self._get_routes()
                for r in routes:
                    if fwutils.get_lte_cache(r.dev_id, 'state') == 'resetting':
                        continue
                    self._check_connectivity(r, server)

            except Exception as e:
                self.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

            # Wait a second before next round, if the current round had no timeouts.
            #
            current_time = time.time()
            if (current_time - prev_time) < 1:
                time.sleep(1)
                prev_time = current_time + 1
            else:
                prev_time = current_time

        self.log.debug("loop stopped")


    def _get_server(self):
        self.current_server = (self.current_server + 1) % self.num_servers
        return self.SERVERS[self.current_server]

    def _get_routes(self):
        '''Fetches routes from Linux and parses them into FwWanRoute objects.
        '''
        os_routes  = {}
        min_metric = sys.maxsize

        routes_linux = fwroutes.FwLinuxRoutes(prefix='0.0.0.0/0')

        for key, route in routes_linux.items():
            if (route.metric % self.WATERMARK) < min_metric:
                route.default = True
                min_metric    = (route.metric % self.WATERMARK)

            # Filter out routes on tunnel interfaces.
            # Tunnels use loopback interfaces that has no physical device, so dev_id should be None.
            #
            if not route.dev_id:
                continue

            # Filter out routes on interfaces where flexiManage disabled monitoring.
            # Note the 'monitorInternet' flag might not exist (in case of device
            # upgrade). In that case we enable the monitoring.
            #
            interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=route.dev_id)
            if interfaces and (interfaces[0].get('monitorInternet', True) == False):
                if not route.dev_id in self.disabled_routes:
                    self.log.debug("disabled on %s(%s)" % (route.dev, route.dev_id))
                    self.disabled_routes[route.dev_id] = route
                continue
            # If monitoring was enabled again, log this.
            if interfaces and route.dev_id in self.disabled_routes:
                self.log.debug("enabled on %s(%s)" % (route.dev, route.dev_id))
                del self.disabled_routes[route.dev_id]

            # Filter out unassigned interfaces, if fwagent_conf.yaml orders that.
            #
            if not interfaces and not fwglobals.g.cfg.MONITOR_UNASSIGNED_INTERFACES:
                if not route.dev_id in self.disabled_routes:
                    self.log.debug("disabled on unassigned %s(%s)" % (route.dev, route.dev_id))
                    self.disabled_routes[route.dev_id] = route
                continue
            # If interface was assigned again, log this.
            if not interfaces and route.dev_id in self.disabled_routes:
                self.log.debug("enabled on unassigned %s(%s)" % (route.dev, route.dev_id))
                del self.disabled_routes[route.dev_id]

            # if this route is known to us, update statistics from cache
            #
            if route.dev_id in self.routes:
                cached = self.routes[route.dev_id]
                route.probes    = cached.probes
                route.ok        = cached.ok
                route.default   = cached.default
            else:
                self.log.debug("Start WAN Monitoring on '%s'" % (str(route)))

            # Finally store the route into cache.
            #
            self.routes[route.dev_id] = route

            # Record keys of routes fetched from OS.
            # We will use them a bit later to remove stale routes from cache.
            #
            os_routes[route.dev_id] = None

        # Remove stale routes from cache
        #
        stale_keys = list(set(self.routes.keys()) - set(os_routes.keys()))
        for key in stale_keys:
            self.log.debug("Stop WAN Monitoring on '%s'" % (str(self.routes[key])))
            del self.routes[key]

        return list(self.routes.values())


    def _check_connectivity(self, route, server):

        cmd = "fping %s -C 1 -q -R -I %s > /dev/null 2>&1" % (server, route.dev)
        ok = not subprocess.call(cmd, shell=True)

        route.probes.append(ok)
        del route.probes[0]             # Keep WINDOWS SIZE

        # At this point we reached WINDOW SIZE, so update WAN connectivity.
        # We use hysteresis to track connectivity state:
        # if connected (metric < watermark), THRESHOLD failures is needed to deduce "no connectivity";
        # if not connected (metric >= watermark), THRESHOLD successes is needed to deduce "connectivity is back"
        #
        successes = route.probes.count(True)
        failures  = self.WND_SIZE - successes

        new_metric = None
        if route.metric < self.WATERMARK and failures >= self.THRESHOLD:
            new_metric = route.metric + self.WATERMARK
            self.log.debug("WAN Monitor: Link down Metric Update - From: %d To: %d" %
                (route.metric, new_metric))
        elif route.metric >= self.WATERMARK and successes >= self.THRESHOLD:
            new_metric = route.metric - self.WATERMARK
            self.log.debug("WAN Monitor: Link up Metric Update - From: %d To: %d" %
                (route.metric, new_metric))

        if new_metric != None:
            state = 'lost' if new_metric >= self.WATERMARK else 'restored'
            self.log.debug("connectivity %s on %s" % (state, route.dev))
            self._update_metric(route, new_metric)


    def _update_metric(self, route, new_metric):
        '''Update route in Linux and in vpp with new metric that reflects lost
        or restore of connectivity.

        :param route:   the route to be updated with new metric
        :param new_metric:  the new metric
        '''
        self.log.debug("'%s' update metric: %d -> %d" % \
            (str(route), route.metric, new_metric))

        # Firsly update the route status, so if get_wan_failover_metric() is called
        # from the other thread it will reflect the actual status.
        #
        prev_ok     = route.ok
        prev_metric = route.metric
        route.ok = True if new_metric < self.WATERMARK else False

        # Go and update Linux.
        # Note we do that directly by 'ip route del' command
        # and not relay on 'netplan apply', as in last case VPPSB does not handle
        # properly kernel NETLINK messsages and does not update VPP FIB.
        #
        success, err_str = fwroutes.add_remove_route("0.0.0.0/0", route.via, route.metric, True, route.dev, route.proto)
        if not success:
            route.ok = prev_ok
            self.log.error("failed to update metric in OS: %s" % err_str)
            return

        fwutils.clear_linux_interfaces_cache()

        # If vpp runs and interface is under vpp control, i.e. assigned,
        # go and adjust vpp configuration to the newer metric.
        # Note the route does not have dev_id for virtual interfaces that are
        # created in vpp/vvpsb by tap-inject for tapcli-X interfaces used for
        # LTE/WiFi devices. These interfaces are assigned too.
        #
        db_if = fwglobals.g.router_cfg.get_interfaces(dev_id=route.dev_id) if route.dev_id else []
        assigned = (not route.dev_id) or (db_if)
        if fwglobals.g.router_api.state_is_started() and assigned:

            # Update netplan yaml-s in order to:
            # 1. Ensure that if 'netplan apply' is called due to some reason
            #    like received 'modify-interface' for other interface the new
            #    metric will be not overrode.
            # 2. Keep interface rule in routing table in sync with metric in default route:
            #       default via 192.168.43.1 dev vpp1 proto dhcp src 192.168.43.99 metric 600
            #       192.168.43.1 dev vpp1 proto dhcp scope link src 192.168.43.99 metric 600
            #
            #
            try:
                name = fwutils.dev_id_to_tap(route.dev_id) # as vpp runs we fetch ip from taps
                if not name:
                    name = route.dev

                ip   = fwutils.get_interface_address(name, log=False)
                proto = route.proto
                dhcp = 'yes' if proto == 'dhcp' else 'no'
                via = route.via
                dev = route.dev

                ifc = db_if[0] if db_if else {}
                mtu = ifc.get('mtu')
                dnsServers  = ifc.get('dnsServers', [])
                # If for any reason, static IP interface comes without static dns servers, we set the default automatically
                if dhcp == 'no' and len(dnsServers) == 0:
                    dnsServers = fwglobals.g.DEFAULT_DNS_SERVERS
                dnsDomains  = ifc.get('dnsDomains', None)

                (success, err_str) = fwnetplan.add_remove_netplan_interface(\
                                        True, route.dev_id, ip, via, new_metric, dhcp, 'WAN', dnsServers, dnsDomains,
                                        mtu, if_name=route.dev, validate_ip=False)
                if not success:
                    route.ok = prev_ok
                    self.log.error("failed to update metric in netplan: %s" % err_str)
                    return
            except Exception as e:
                self.log.error("_update_metric failed: %s" % str(e))

        # If defult route was changes as a result of metric update,
        # reconnect agent to flexiManage.
        #
        if route.default:
            fwglobals.g.fwagent.reconnect()

        self.log.debug("'%s' update metric: %d -> %d - done" % \
            (str(route), route.metric, new_metric))


def get_wan_failover_metric(dev_id, metric):
    '''Fetches the metric of the default route on the device with specified dev_id.
    The metric might be the real one configured by user on flexiManage
    if internet is reachable via this device, or it can be the watermarked metric
    (the configured by user + WATERMARK) if internet is not reachable.

    :param dev_id:  Bus address of the device, default route of which is required for metric
    :param metric:  the original metric configured by user
    '''
    route = fwglobals.g.cache.wan_monitor['enabled_routes'].get(dev_id)
    if not route or route.ok or metric >= fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK:
        return metric
    return (metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK)
