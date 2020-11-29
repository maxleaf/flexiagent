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

    :param standalone: if True, the module does nothing. It is used for tests.
                       The 'standalone' stands for the agent mode and means,
                       that the agent is not connected to internet.
    """
    def __init__(self, standalone):
        """Constructor method
        """
        self.standalone = standalone
        if self.standalone:
            return

        # Make few shortcuts to get more readable code
        #
        self.SERVERS                = fwglobals.g.WAN_FAILOVER_SERVERS
        self.WND_SIZE               = fwglobals.g.WAN_FAILOVER_WND_SIZE
        self.THRESHOLD              = fwglobals.g.WAN_FAILOVER_WND_SIZE
        self.NET_RESTART_THRESHOLD  = fwglobals.g.WAN_FAILOVER_NET_RESTART_TH
        self.METRIC_WATERMARK       = fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK

        self.num_servers    = len(self.SERVERS)
        self.current_server = self.num_servers - 1  # The first selection will take #0
        self.routes         = {}
        self.route_rule_re  = re.compile(r"(\w+) via ([0-9.]+) dev (\w+)(.*)") #  'default via 20.20.20.22 dev enp0s9 proto dhcp metric 100'

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
        '''Fetches routes from Linux and parses them into list of structures:
        {
            'prefix':   'default'/<prefix, e.g. '20.20.20.0/24'>
            'via':      <gw, e.g. '192.168.1.1'>
            'dev_name': <name, e.g. 'enp0s8'>,
            'dev_pci':  <pci in full form, e.g. "0000:00:08.00">
            'metric':   <metric>/0 - OPTIONAL, may not present!
            'proto':    'static'/'dhcp'/''
        }
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
                continue

            route = {}
            route['prefix']     = m.group(1)
            route['via']        = m.group(2)
            route['dev_name']   = m.group(3)
            pci, _ = fwutils.get_interface_pci(route['dev_name'])
            route['dev_pci']    = pci
            route['proto']      = 'static'
            route['probes']     = []
            route['failures']   = 0
            if m.group(4):  # proto and metric are optional, so parse them manually
                if 'proto ' in m.group(4):
                    route['proto']  = m.group(4).split('proto ')[1].split(' ')[0]
                if 'metric ' in m.group(4):
                    route['metric'] = int(m.group(4).split('metric ')[1].split(' ')[0])

            # Filter out routes on some interfaces.
            #
            interfaces = fwglobals.g.router_cfg.get_interfaces(pci=pci)
            # Filter out interfaces that were marked by flexiManage as "no need to monitor"
            if interfaces and interfaces[0].get('monitor-internet', False) == False:
                continue
            # Filter out unassigned interfaces, if fwagent_conf.yaml orders that.
            if not interfaces and not fwglobals.g.cfg.MONITOR_UNASSIGNED_INTERFACES:
                continue

            # if this route is known to us, update counters from cache
            #
            key = route['prefix'] + '---' + route['dev_pci']
            if key in self.routes:
                route['probes']   = self.routes[key]['probes']
                route['failures'] = self.routes[key]['failures']
            else:
                # Suppress RPF permanently to avoid Linux to filter out
                # responses for ping-s on not default route interfaces.
                fwutils.set_linux_reverse_path_filter(route['dev_name'], on=False)
                fwglobals.log.debug("%s: add '%s'" % (str(self), _str_route(route)))

            # Finally store the route [back] into cache.
            #
            self.routes[key] = route

            # Record keys of routes fetched from OS.
            # We will use them a bit later to remove stale routes from cache.
            #
            os_routes[key] = None

        # Remove stale routes from cache
        #
        stale_keys = list(set(self.routes.keys()) - set(os_routes.keys())) 
        for key in stale_keys:
            fwglobals.log.debug("%s: remove '%s'" % (str(self), _str_route(self.routes[key])))
            del self.routes[key]

        return self.routes.values()


    def _check_connectivity(self, route, server):

        cmd = "fping %s -C 1 -q -I %s" % (server, route['dev_name'])
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        rtt = out.split(' : ')[1].strip()   # On success: "8.8.8.8 : 73.43", on failure: "8.8.8.8 : -"
        ok  = False if rtt == '-' else True

        route['probes'].append(ok)
        if len(route['probes']) > self.WND_SIZE:
            del route['probes'][0]

        # Restart network on reaching X subsequent failures (we are desperated)
        #
        if not ok:
            route['failures'] += 1
            if route['failures'] == self.NET_RESTART_THRESHOLD:
                fwglobals.log.debug("%s: %d subsequent fails on %s - restart networkd" %
                    (str(self), self.NET_RESTART_THRESHOLD, route['dev_name']))
                os.system('systemctl status systemd-networkd')
                fwglobals.log.debug("%s: networkd was restarted" % str(self))
                route['failures'] = 0

        if len(route['probes']) != self.WND_SIZE:
            return ok

        # WINDOW SIZE was reached, update WAN connectivity.
        # We use hysteresis to track connectivity state:
        # if connected (metric < watermark), THRESHOLD failures is needed to deduce "no connectivity";
        # if not connected (metric >= watermark), THRESHOLD successes is needed to deduce "connectivity is back"
        #
        successes = route['probes'].count(True)
        failures  = self.WND_SIZE - successes

        metric = route.get('metric', 0)
        if metric < self.METRIC_WATERMARK and failures >= self.THRESHOLD:
            fwglobals.log.debug("%s: connectivity lost on %s" % (str(self), route['name']))
            new_metric = metric + self.METRIC_WATERMARK
            self._flush_route(route, new_metric)

        if metric >= self.METRIC_WATERMARK and successes >= self.THRESHOLD:
            fwglobals.log.debug("%s: connectivity restored on %s" % (str(self), route['name']))
            new_metric = metric - self.METRIC_WATERMARK
            self._flush_route(route, new_metric)


    def _flush_route(self, route, metric):
        '''Update route in Linux and in vpp with new metric that reflects
        connectivity lost or restore.

        :param route:   the route to be updated with new metric
        :param metric:  the new metric
        '''
        route_str = _str_route(route)
        fwglobals.log.debug("%s: '%s' update metric in OS: %d -> %d" % \
            (str(self), route_str, str(route.get('metric', 0)), str(metric)))

        if metric < 0 or metric > (self.METRIC_WATERMARK * 2):
            fwglobals.log.error("%s: not expected metric %d for %s" %
                (str(self), metric, route['dev_name']))
            return

        # Firstly update router configuration database.
        # To do that we inject 'modify-device' request with new metric,
        # as it would be received from .
        #
        interfaces      = fwglobals.g.router_cfg.get_interfaces(type='wan', pci=route['dev_pci'])
        interface_in_db = len(interfaces) > 0
        if interface_in_db:
            request = {
                'message': 'modify-interface',
                'params': {
                    'pci': route['dev_pci'],
                    'metric': metric
                }
            }
            try:
                ret = fwglobals.g.router_api.call(request)
            except Exception as e:
                ret = { 'ok': 0, 'message': str(e) }
            if 'ok' in ret and ret['ok'] == 0:
                fwglobals.log.error("%s: failed to inject %s: %s" %
                    (str(self), json.dumps(request), ret['message']))
                # Don't return here, continue and update metric directly in Linux

        # Now, if vpp runs, we done, as Linux routing table will be updated
        # by the router_api while handling the injected 'modify-interface'.
        # If vpp does not run, we have to update Linux explicitly.
        #
        if interface_in_db and fwglobals.g.router_api.router_started:
            return

        # Firstly remove the route with the current metric.
        #
        old_metric = '' if not 'metric' in route else str(route['metric'])
        (ok, err_str) = fwutils.add_static_route(
                                    route['prefix'], route['via'], old_metric, True,
                                    pci=route['dev_pci'], enable_default=True)
        if not ok:
            fwglobals.log.error("%s: '%s': failed to remove route from OS: %s" % \
                (str(self), route_str, err_str))
            return

        # Now add the route with modified metric.
        #
        (ok, err_str) = fwutils.add_static_route(
                                    route['prefix'], route['via'], str(metric), False,
                                    pci=route['dev_pci'], enable_default=True)
        if not ok:
            fwglobals.log.error("%s: '%s': failed to update metric in OS (new metric %d)" %
                                (str(self), route_str, metric))
            return

        # Ensure that connection to flexiManage was revived after metric update.
        #
        fwglobals.g.fwagent.reconnect()

        fwglobals.log.debug("%s: '%s' update metric in OS: %d -> %d - done" % \
            (str(self), route_str, str(route.get('metric', 0)), str(metric)))


    def _restore_metrics(self):
        '''On FwWanMonitor/agent initialization updates Linux with metrics found
        in router configuration database. This is needed to reduce failover time
        when vpp does not run.
        '''
        routes     = self._get_routes()
        interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
        for interface in interfaces:
            metric_in_db = interface.get('metric')
            if metric_in_db:
                for r in routes:
                    metric_in_os = r.get('metric', 0)
                    if r['dev_pci'] == interface['pci'] and metric_in_os != metric_in_db:
                        fwglobals.log.debug("%s: restore metric on %s" % (str(self), r['dev_name']))
                        self._flush_route(r, metric_in_db)

def _str_route(route):
    metric_str = '' if not 'metric' in route else ' metric ' + str(route['metric'])
    route_str = '%s via %s dev %s(%s) proto %s%s' % \
                (route['prefix'],  route['via'],   route['dev_name'],
                 route['dev_pci'], route['proto'], metric_str)
    return route_str

