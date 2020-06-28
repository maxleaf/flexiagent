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
import yaml
import sys
import os
from shutil import copyfile
import fwglobals
import fwstats
import fwutils

fwagent_api = {
    'get-device-info':          '_get_device_info',
    'get-device-stats':         '_get_device_stats',
    'get-device-logs':          '_get_device_logs',
    'get-device-packet-traces': '_get_device_packet_traces',
    'get-device-os-routes':     '_get_device_os_routes',
    'get-router-config':        '_get_router_config',
    'upgrade-device-sw':        '_upgrade_device_sw',
    'reset-device':             '_reset_device_soft',
    'sync-device':              '_sync_device',
}

class FWAGENT_API:
    """This class implements fwagent level APIs of flexiEdge device.
       Typically these APIs are used to monitor various components of flexiEdge.
       They are invoked by the flexiManage over secure WebSocket
       connection using JSON requests.
       For list of available APIs see the 'fwagent_api' variable.
    """
    def call(self, req, params):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        handler = fwagent_api.get(req)
        assert handler, 'fwagent_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwagent_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwagent_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _get_device_info(self, params):
        """Get device information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            info = {}
            # Load component versions
            with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
                info = yaml.load(stream, Loader=yaml.BaseLoader)
            # Load network configuration.
            info['network'] = {}
            info['network']['interfaces'] = fwglobals.g.handle_request('interfaces')['message']
            utils_default_route = fwutils.get_default_route()
            default_route = {
                "addr": "default",
                "via": utils_default_route[0],
                "pci": fwutils.linux_to_pci_addr(utils_default_route[1])[0]
                }
            info['network']['routes'] = [ default_route ]
            return {'message': info, 'ok': 1}
        except:
            raise Exception("_get_device_info: failed to get device info: %s" % format(sys.exc_info()[1]))

    def _get_device_stats(self, params):
        """Get device and interface statistics.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with statistics.
        """
        reply = fwstats.get_stats()

        # Add router configuration hash to assist database synchronization feature
        reply['router-cfg-hash'] = fwglobals.g.router_api.db_requests.get_signature()

        return reply

    def _upgrade_device_sw(self, params):
        """Upgrade device SW.

        :param params: Parameters from flexiManage.

        :returns: Message and status code.
        """
        dir = os.path.dirname(os.path.realpath(__file__))

        # Copy the fwupgrade.sh file to the /tmp folder to
        # prevent overriding it with the fwupgrade.sh file
        # from the new version.
        try:
            copyfile('{}/fwupgrade.sh'.format(dir), '/tmp/fwupgrade.sh')
        except Exception as e:
            return { 'message': 'Failed to copy upgrade file', 'ok': 0 }

        cmd = 'bash /tmp/fwupgrade.sh {} {} {} {} >> {} 2>&1 &' \
            .format(params['version'], fwglobals.g.VERSIONS_FILE, \
                    fwglobals.g.CONN_FAILURE_FILE, \
                    fwglobals.g.ROUTER_LOG_FILE, \
                    fwglobals.g.ROUTER_LOG_FILE)
        os.system(cmd)
        return { 'message': 'Started software upgrade process', 'ok': 1 }

    def _get_device_logs(self, params):
        """Get device logs.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with logs and status code.
        """
        dl_map = {
    	    'fwagent': fwglobals.g.ROUTER_LOG_FILE,
    	    'syslog': fwglobals.g.SYSLOG_FILE,
            'dhcp': fwglobals.g.DHCP_LOG_FILE,
            'vpp': fwglobals.g.VPP_LOG_FILE,
            'ospf': fwglobals.g.OSPF_LOG_FILE,
	    }
        file = dl_map.get(params['filter'], '')
        try:
            logs = fwutils.get_device_logs(file, params['lines'])
            return {'message': logs, 'ok': 1}
        except:
            raise Exception("_get_device_logs: failed to get device logs: %s" % format(sys.exc_info()[1]))

    def _get_device_packet_traces(self, params):
        """Get device packet traces.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with logs and status code.
        """
        try:
            traces = fwutils.get_device_packet_traces(params['packets'], params['timeout'])
            return {'message': traces, 'ok': 1}
        except:
            raise Exception("_get_device_packet_traces: failed to get device packet traces: %s" % format(sys.exc_info()[1]))

    def _get_device_os_routes(self, params):
        """Get device ip routes.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with routes and status code.
        """
        routing_table = fwutils.get_os_routing_table()

        if routing_table == None:
            raise Exception("_get_device_os_routes: failed to get device routes: %s" % format(sys.exc_info()[1]))

        # Remove empty lines and the headers of the 'route' command
        routing_table = [ el for el in routing_table if (el is not "" and routing_table.index(el)) > 1 ]
        route_entries = []

        for route in routing_table:
            fields = route.split()
            if len(fields) < 8:
                raise Exception("_get_device_os_routes: failed to get device routes: parsing failed")

            route_entries.append({
                'destination': fields[0],
                'gateway': fields[1],
                'mask': fields[2],
                'flags': fields[3],
                'metric': fields[4],
                'interface': fields[7],
            })

        return {'message': route_entries, 'ok': 1}

    def _get_router_config(self, params):
        """Get router configuration from DB.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with configuration and status code.
        """
        configs = fwutils.get_router_config()
        reply = {'ok': 1, 'message': configs if configs != None else {}}
        return reply

    def _reset_device_soft(self, params=None):
        """Soft reset device configuration.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        if fwglobals.g.router_api.router_started:
            fwglobals.g.router_api.call('stop-router')   # Stop VPP if it runs
        fwutils.reset_router_config()
        return {'ok': 1}

    def _sync_device(self, params):
        """Synchronize VPP state to the configuration stored on flexiManage.
        The synchronization can be full or partial. The last is not supported yet.
        In full case all interfaces, tunnels, routes, etc, that do not appear
        in the received from server configuration are removed, all entities
        that do appear in server version but do not appear on device are added
        and all entities that appear in both but are different are modified.
        The same entities are ignored.

        :param params: Parameters from flexiManage - 'add-X' requests.

        :returns: Dictionary with status code.
        """
        fwglobals.log.info("FWAGENT_API: _sync_device started")

        remote_signature = params['router-cfg-hash']
        local_signature  = fwglobals.g.router_api.db_requests.get_signature()
        if remote_signature == local_signature:
            fwglobals.log.info(
                "FWAGENT_API: _sync_device: no need to sync: received=stored=%s finished" %
                local_signature)
            return {'ok': 1}

        # Below is the temporary rude implementation:
        # soft reset device and load received configuration.
        # Later we will implement more elegant solution described above :)
        restart_router = fwglobals.g.router_api.router_started
        self._reset_device_soft()
        for request in params['requests']:
            reply = fwglobals.g.router_api.call(request['msg'], request.get('params'))
            if reply['ok'] == 0:
                raise Exception("FWAGENT_API: _sync_device failed (%s)" % str(reply.get('message')))
        if restart_router:
            fwglobals.g.router_api.call('start-router')
        fwglobals.g.router_api.db_requests.reset_signature()

        fwglobals.log.info("FWAGENT_API: _sync_device finished")
        return {'ok': 1}
