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
import threading
import time
import traceback

import fwglobals
import fwutils

class FwWanRoute:
    """The object that represents routing rule found in OS.
    In addition it keeps statistics about internet connectivity on this route.
    """
    def __init__(self, prefix, via, dev, metric=0):
        self.prefix     = prefix
        self.via        = via
        self.dev        = dev
        self.metric     = metric
        self.dev_id     = fwutils.get_interface_dev_id(dev)
        self.key        = prefix + '---' + self.dev_id
        self.probes     = []      # List of ping results

    def __str__(self):
        route = '%s via %s dev %s(%s)' % (self.prefix, self.via, self.dev, self.dev_id)
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

        # On initialization due to either device reboot or daemon restart
        # if vpp does not run, apply metrics found in router configuration.
        # This is to reduce period of 'no connection to flexiManage'.
        #
        if not fwglobals.g.router_api.router_started:
            self._restore_metrics()

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

                while fwglobals.g.router_api.is_starting_stopping():
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
        os_routes = {}

        cmd = 'ip route list match default | grep via'
        try:
            out = subprocess.check_output(cmd, shell=True).splitlines()
        except Exception as e:
            fwglobals.log.warning("%s: no default routes found: %s" % (str(self), str(e)))
            out = []

        for line in out:
            m = self.route_rule_re.match(line)
            if not m:
                fwglobals.log.debug("%s: not expected format: '%s'" % (str(self), line))
                continue

            route = FwWanRoute(prefix=m.group(1), via=m.group(2), dev=m.group(3))
            if m.group(4) and 'metric ' in m.group(4):
                route.metric = int(m.group(4).split('metric ')[1].split(' ')[0])

            # Filter out routes on interfaces where flexiManage disabled monitoring.
            # Note the 'monitorInternet' flag might not exist (in case of device
            # upgrade). In that case we enable the monitoring.
            #
            interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=route.dev_id)
            if interfaces and (interfaces[0].get('monitorInternet', True) == False):
                if not route.key in self.disabled_routes:
                    fwglobals.log.debug("%s: disabled on %s(%s)" % (str(self), route.dev, route.dev_id))
                    self.disabled_routes[route.key] = route
                continue
            # If monitoring was enables again, log this.
            if interfaces and route.key in self.disabled_routes:
                fwglobals.log.debug("%s: enabled on %s(%s)" % (str(self), route.dev, route.dev_id))
                del self.disabled_routes[route.key]

            # Filter out unassigned interfaces, if fwagent_conf.yaml orders that.
            #
            if not interfaces and not fwglobals.g.cfg.MONITOR_UNASSIGNED_INTERFACES:
                if not route.key in self.disabled_routes:
                    fwglobals.log.debug("%s: disabled on unassigned %s(%s)" % (str(self), route.dev, route.dev_id))
                    self.disabled_routes[route.key] = route
                continue
            # If interface was assigned again, log this.
            if not interfaces and route.key in self.disabled_routes:
                fwglobals.log.debug("%s: enabled on unassigned %s(%s)" % (str(self), route.dev, route.dev_id))
                del self.disabled_routes[route.key]

            # if this route is known to us, update statistics from cache
            #
            if route.key in self.routes:
                route.probes = self.routes[route.key].probes
            else:
                # Suppress RPF permanently to avoid Linux to filter out
                # responses for ping-s on not default route interfaces.
                fwutils.set_linux_reverse_path_filter(route.dev, on=False)
                fwglobals.log.debug("%s: start on '%s'" % (str(self), str(route)))

            # Finally store the route into cache.
            #
            self.routes[route.key] = route

            # Record keys of routes fetched from OS.
            # We will use them a bit later to remove stale routes from cache.
            #
            os_routes[route.key] = None

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
        if len(route.probes) > self.WND_SIZE:
            del route.probes[0]

        if len(route.probes) < self.WND_SIZE:
            return ok

        # At this point we reached WINDOW SIZE, update WAN connectivity.
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

        # Go and update Linux.
        # Do this before update in router configuration database, as the last
        # calls netplan apply that might cause  duplicated routes.
        #
        try:
            cmd = "ip route show exact %s dev %s" % (route.prefix, route.dev)
            os_route = subprocess.check_output(cmd, shell=True).strip()
            if not os_route:
                raise Exception("'%s' returned nothing" % cmd)
            cmd = "ip route del " + os_route
            ok = not subprocess.call(cmd, shell=True)
            if not ok:
                raise Exception("'%s' failed" % cmd)
            if 'metric ' in os_route:  # Replace metric in os route string
                os_route = re.sub('metric [0-9]+', 'metric %d' % new_metric, os_route)
            else:
                os_route += ' metric %d' % new_metric
            cmd = "ip route add " + os_route
            ok = not subprocess.call(cmd, shell=True)
            if not ok:
                raise Exception("'%s' failed" % cmd)
        except Exception as e:
            fwglobals.log.error("%s: failed to update metric: %s" % (str(self), str(e)))
            return

        # Now  update router configuration database, so the new metric will
        # persist device reboot. To do that we inject 'modify-device' request
        # with the new metric, as it would be received from flexiManage.
        # Note actually we do not store new metric, but just add or remove
        # watermark to the metric kept in database. So if meanwhile user updated
        # interface metric on flexiManage, it will be not overrode by us.
        #
        try:
            interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan', dev_id=route.dev_id)
            if interfaces:
                if_metric_str = interfaces[0].get('metric')
                if_metric     = int(if_metric_str) if if_metric_str else 0
                if if_metric >= self.WATERMARK and new_metric < self.WATERMARK:
                    if_metric -= self.WATERMARK
                elif if_metric < self.WATERMARK and new_metric >= self.WATERMARK:
                    if_metric += self.WATERMARK
                else:
                    # If router configuration DB was already watermarked/un-watermarked
                    # escape the update. Note that might happen on agent initialization,
                    # when OS routes are updated according watermarksin DB.
                    # Or on unexpected flow ;)
                    raise UnboundLocalError(
                            "monitor is out of sync (new metric: %d, stored metric: %d)" % \
                            (new_metric, if_metric))

                if if_metric != new_metric:
                    fwglobals.log.debug("%s: user updated metric meanwhile, keep it: %d" % (str(self), if_metric))

                request = {
                    'message': 'modify-interface',
                    'params': {
                        'dev_id':    route.dev_id,
                        'metric':    unicode(str(if_metric)),   # DB keeps strings in 'unicode' as this is what json.loads() uses
                        'internals': { 'sender': str(self) }
                    }
                }
                ret = fwglobals.g.router_api.call(request)
                if ret.get('ok', 1) == 0:
                    raise Exception(ret.get('message', 'failed to inject modify-interface'))

        except UnboundLocalError as e:
            fwglobals.log.debug("%s: skip router configuration update: %s" % (str(self), str(e)))
            pass
        except Exception as e:
            fwglobals.log.error("%s: failed to update router configuration: %s" % (str(self), str(e)))
            # Don't return here, as metrics were updated already in Linux and we do not rollback them for now

        # Ensure that connection to flexiManage was revived after metric update.
        # Note if vpp runs, the reconnection will be made during execution of
        # the injected 'modify-interface', so there is no need to reconnect here.
        #
        if not fwglobals.g.router_api.router_started:
            fwglobals.g.fwagent.reconnect()

        fwglobals.log.debug("%s: '%s' update metric in OS: %d -> %d - done" % \
            (str(self), str(route), route.metric, new_metric))


    def _restore_metrics(self):
        '''On FwWanMonitor/agent initialization updates Linux with 'bad' routes,
        based on the watermarked metrics found in router configuration database.
        This is needed to reduce failover time on agent start, when vpp does not run.
        '''
        routes     = self._get_routes()
        interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
        for interface in interfaces:
            metric_in_db = interface.get('metric')
            metric_in_db = 0 if not metric_in_db else int(metric_in_db)
            if metric_in_db >= self.WATERMARK:
                for r in routes:
                    if r.dev_id == interface['dev_id']:
                        fwglobals.log.debug("%s: restore DOWN state of '%s'" % (str(self), str(r)))
                        r.probes = [ False ] * self.WND_SIZE
