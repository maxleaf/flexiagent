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

import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback

import fwglobals
import fwnetplan
import fwutils

class FwWanRoute:
    """The object that represents routing rule found in OS.
    In addition it keeps statistics about internet connectivity on this route.
    """
    def __init__(self, prefix, via, dev, proto=None, metric=0):
        self.prefix     = prefix
        self.via        = via
        self.dev        = dev
        self.proto      = proto
        self.metric     = metric
        self.pci,_      = fwutils.get_interface_pci(dev)
        self.probes     = [True] * fwglobals.g.WAN_FAILOVER_WND_SIZE    # List of ping results
        self.ok         = True      # If True there is connectivity to internet
        self.default    = False     # If True the route is the default one - has lowest metric

    def __str__(self):
        route = '%s via %s dev %s(%s)' % (self.prefix, self.via, self.dev, self.pci)
        if self.proto:
            route += (' proto ' + str(self.proto))
        if self.metric:
            route += (' metric ' + str(self.metric))
        return route

class FwWanMonitor:
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

        self.active           = True
        self.thread_main_loop = threading.Thread(target=self.main_loop, name=str(self))
        self.thread_main_loop.start()

    def __str__(self):  # Make str(self) prints the class name
        return self.__class__.__name__

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        if self.standalone:
            return
        self.active = False
        if self.thread_main_loop:
            self.thread_main_loop.join()
            self.thread_main_loop = None


    def main_loop(self):
        fwglobals.log.debug("%s: loop started" % str(self))

        prev_time = time.time()

        while self.active:

            try: # Ensure thread doesn't exit on exception

                while fwglobals.g.router_api.state_is_starting_stopping():
                    fwglobals.log.debug("%s: vpp is being started/stopped" % str(self))
                    time.sleep(5)

                server = self._get_server()
                routes = self._get_routes()
                for r in routes:
                    self._check_connectivity(r, server)

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
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

        fwglobals.log.debug("%s: loop stopped" % str(self))


    def _get_server(self):
        self.current_server = (self.current_server + 1) % self.num_servers
        return self.SERVERS[self.current_server]

    def _get_routes(self):
        '''Fetches routes from Linux and parses them into FwWanRoute objects.
        '''
        os_routes  = {}
        min_metric = sys.maxint

        out = []
        cmd = 'ip route list match default | grep via'
        for _ in range(5):
            try:
                out = subprocess.check_output(cmd, shell=True).splitlines()
                break
            except Exception as e:
                fwglobals.log.warning("%s: no default routes found: %s" % (str(self), str(e)))
                time.sleep(1)

        for line in out:
            m = self.route_rule_re.match(line)
            if not m:
                fwglobals.log.debug("%s: not expected format: '%s'" % (str(self), line))
                continue

            route = FwWanRoute(prefix=m.group(1), via=m.group(2), dev=m.group(3))
            if m.group(4) and 'proto ' in m.group(4):
                route.proto = m.group(4).split('proto ')[1].split(' ')[0]
            if m.group(4) and 'metric ' in m.group(4):
                route.metric = int(m.group(4).split('metric ')[1].split(' ')[0])

            if (route.metric % self.WATERMARK) < min_metric:
                route.default = True
                min_metric    = (route.metric % self.WATERMARK)

            # Filter out routes on interfaces where flexiManage disabled monitoring.
            # Note the 'monitorInternet' flag might not exist (in case of device
            # upgrade). In that case we enable the monitoring.
            #
            interfaces = fwglobals.g.router_cfg.get_interfaces(pci=route.pci)
            if interfaces and (interfaces[0].get('monitorInternet', True) == False):
                if not route.pci in self.disabled_routes:
                    fwglobals.log.debug("%s: disabled on %s(%s)" % (str(self), route.dev, route.pci))
                    self.disabled_routes[route.pci] = route
                continue
            # If monitoring was enabled again, log this.
            if interfaces and route.pci in self.disabled_routes:
                fwglobals.log.debug("%s: enabled on %s(%s)" % (str(self), route.dev, route.pci))
                del self.disabled_routes[route.pci]

            # Filter out unassigned interfaces, if fwagent_conf.yaml orders that.
            #
            if not interfaces and not fwglobals.g.cfg.MONITOR_UNASSIGNED_INTERFACES:
                if not route.pci in self.disabled_routes:
                    fwglobals.log.debug("%s: disabled on unassigned %s(%s)" % (str(self), route.dev, route.pci))
                    self.disabled_routes[route.pci] = route
                continue
            # If interface was assigned again, log this.
            if not interfaces and route.pci in self.disabled_routes:
                fwglobals.log.debug("%s: enabled on unassigned %s(%s)" % (str(self), route.dev, route.pci))
                del self.disabled_routes[route.pci]

            # if this route is known to us, update statistics from cache
            #
            if route.pci in self.routes:
                cached = self.routes[route.pci]
                route.probes    = cached.probes
                route.ok        = cached.ok
                route.default   = cached.default
            else:
                # Suppress RPF permanently to avoid Linux to filter out
                # responses for ping-s on not default route interfaces.
                fwutils.set_linux_reverse_path_filter(route.dev, on=False)
                fwglobals.log.debug("%s: start on '%s'" % (str(self), str(route)))

            # Finally store the route into cache.
            #
            self.routes[route.pci] = route

            # Record keys of routes fetched from OS.
            # We will use them a bit later to remove stale routes from cache.
            #
            os_routes[route.pci] = None

        # Remove stale routes from cache
        #
        stale_keys = list(set(self.routes.keys()) - set(os_routes.keys()))
        for key in stale_keys:
            fwglobals.log.debug("%s: stop on '%s'" % (str(self), str(self.routes[key])))
            del self.routes[key]

        return self.routes.values()


    def _check_connectivity(self, route, server):

        cmd = "fping %s -C 1 -q -I %s > /dev/null 2>&1" % (server, route.dev)
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
        elif route.metric >= self.WATERMARK and successes >= self.THRESHOLD:
            new_metric = route.metric - self.WATERMARK

        if new_metric != None:
            state = 'lost' if new_metric >= self.WATERMARK else 'restored'
            fwglobals.log.debug("%s: connectivity %s on %s" % (str(self), state, route.dev))
            self._update_metric(route, new_metric)


    def _update_metric(self, route, new_metric):
        '''Update route in Linux and in vpp with new metric that reflects lost
        or restore of connectivity.

        :param route:   the route to be updated with new metric
        :param new_metric:  the new metric
        '''
        fwglobals.log.debug("%s: '%s' update metric in OS: %d -> %d" % \
            (str(self), str(route), route.metric, new_metric))

        # Firsly update the route status, so if get_wan_failover_metric() is called
        # from the other thread it will reflect the actual status.
        #
        prev_ok     = route.ok
        prev_metric = route.metric
        route.ok = True if new_metric < self.WATERMARK else False

        # Go and update Linux.
        # Note we do that directly by 'ip route del' & 'ip route add' commands
        # and not relay on 'netplan apply', as in last case VPPSB does not handle
        # properly kernel NETLINK messsages and does not update VPP FIB.
        #
        success, err_str = fwutils.update_linux_metric(route.prefix, route.dev, new_metric)
        if not success:
            route.ok = prev_ok
            fwglobals.log.error("%s: failed to update metric in OS: %s" % (str(self), err_str))
            return

        # If vpp runs, go and adjust it configuration to the newer metric.
        #
        if fwglobals.g.router_api.state_is_started():

            # Update netplan yaml-s in order to:
            # 1. Ensure that if 'netplan apply' is called due to some reason
            #    like received 'modify-interface' for other interface the new
            #    metric will be not overrode.
            # 2. Keep interface rule in routing table in sync with metric in default route:
            #       default via 192.168.43.1 dev vpp1 proto dhcp src 192.168.43.99 metric 600
            #       192.168.43.1 dev vpp1 proto dhcp scope link src 192.168.43.99 metric 600
            #
            ip   = fwutils.get_interface_address(route.dev, log=False)
            dhcp = 'yes' if route.proto == 'dhcp' else 'no'
            (success, err_str) = fwnetplan.add_remove_netplan_interface(\
                                    True, route.pci, ip, route.via, new_metric, dhcp, 'WAN',
                                    if_name=route.dev, wan_failover=True)
            if not success:
                route.ok = prev_ok
                fwglobals.log.error("%s: failed to update metric in netplan: %s" % (str(self), err_str))
                fwutils.update_linux_metric(route.prefix, route.dev, route.metric)
                return

            # Update VPP NAT with the new default route interface.
            #
            if route.default:
                success = fwutils.vpp_nat_add_remove_interface(False, route.pci, new_metric)
                if not success:
                    route.ok = prev_ok
                    fwglobals.log.error("%s: failed to update metric in VPP NAT" % (str(self)))
                    fwutils.update_linux_metric(route.prefix, route.dev, route.metric)
                    fwnetplan.add_remove_netplan_interface(\
                        True, route.pci, ip, route.via, prev_metric, dhcp, 'WAN',
                        if_name=route.dev, wan_failover=True)
                    return

        # If defult route was changes as a result of metric update,
        # reconnect agent to flexiManage.
        #
        if route.default:
            fwglobals.g.fwagent.reconnect()

        fwglobals.log.debug("%s: '%s' update metric in OS: %d -> %d - done" % \
            (str(self), str(route), route.metric, new_metric))


def get_wan_failover_metric(pci, metric):
    '''Fetches the metric of the default route on the device with specified PCI.
    The metric might be the real one configured by user on flexiManage
    if internet is reachable via this device, or it can be the watermarked metric
    (the configured by user + WATERMARK) if internet is not reachable.

    :param pci:     PCI of the device, default route of which is required for metric
    :param metric:  the original metric configured by user
    '''
    route = fwglobals.g.cache.wan_monitor['enabled_routes'].get(pci)
    if not route or route.ok or metric >= fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK:
        return metric
    return (metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK)
