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
import re
from shutil import copyfile
import subprocess
import time
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
    'modify-device':            '_modify_device'
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

    def _prepare_tunnel_info(self, tunnel_ids):
        tunnel_info = []
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        for params in tunnels:
            try:
                tunnel_id = params["tunnel-id"]
                if tunnel_id in tunnel_ids:
                    # key1-key4 are the crypto keys stored in
                    # the management for each tunnel
                    tunnel_info.append({
                        "id": str(tunnel_id),
                        "key1": params["ipsec"]["local-sa"]["crypto-key"],
                        "key2": params["ipsec"]["local-sa"]["integr-key"],
                        "key3": params["ipsec"]["remote-sa"]["crypto-key"],
                        "key4": params["ipsec"]["remote-sa"]["integr-key"]
                    })

            except Exception as e:
                fwglobals.log.excep("failed to create tunnel information %s" % str(e))
                raise e
        return tunnel_info

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
            info['reconfig'] = fwutils.get_reconfig_hash()
            # Load tunnel info, if requested by the management
            if params and params['tunnels']:
                info['tunnels'] = self._prepare_tunnel_info(params['tunnels'])
                
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
        reply['router-cfg-hash'] = fwglobals.g.router_cfg.get_signature()

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
        configs = fwutils.dump_router_config()
        reply = {'ok': 1, 'message': configs if configs else {}}
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
        """Handles the 'sync-device' request: synchronizes VPP state
        to the configuration stored on flexiManage. During synchronization
        all interfaces, tunnels, routes, etc, that do not appear
        in the received 'sync-device' request are removed, all entities
        that do appear in the request but do not appear on device are added
        and all entities that appear in both but are different are modified.
        The same entities are ignored.

        :param params: Request parameters received from flexiManage:
                        {
                          'router-cfg-hash': <the signature of the device
                                    configuration stored on flexiManage>
                          'requests': <list of 'add-X' requests that represent
                                    device configuration stored on flexiManage>
                        }
        :returns: Dictionary with status code.
        """
        fwglobals.log.info("FWAGENT_API: _sync_device STARTED")

        # Check if there is a need to sync at all.
        # It might be race between receiving sync-device request from server
        # and sending success reply to the previous request, so server might
        # deduce that we out of sync, when we are OK.
        # So we ensure that the configuration signature received from server
        # differs from the one of the current configuration. If it is not,
        # we are OK - simply return.
        #
        remote_signature = params['router-cfg-hash']
        local_signature  = fwglobals.g.router_cfg.get_signature()
        fwglobals.log.debug(
            "FWAGENT_API: _sync_device: cfg signature: received=%s, stored=%s" %
            (remote_signature, local_signature))
        if remote_signature == local_signature:
            fwglobals.log.info("FWAGENT_API: _sync_device: no need to sync")
            fwglobals.g.router_cfg.reset_signature()
            return {'ok': 1}

        # Now go over configuration requests received within sync-device request,
        # intersect them against the requests stored locally and generate new list
        # of remove-X and add-X requests that should take device to configuration
        # received with the sync-device.
        #
        sync_list = fwglobals.g.router_cfg.get_sync_list(params['requests'])

        # Find out if sync goes to remove or to add new interfaces.
        # In this case the vpp should be restarted in order to release/capture
        # correspondent devices.
        # Note the modified interfaces do not require restart, so we should
        # filter out 'remove-interface' requests that have correspondent 'add-
        # interface' requests. The criteria for match is pci.
        #
        restart_router = False
        if fwglobals.g.router_api.router_started:
            interfaces = {}
            for request in sync_list:
                if re.search('-interface', request['message']):
                    pci = request['params']['pci']
                    if pci in interfaces:
                        del interfaces[pci]
                    else:
                        interfaces[pci] = None
            restart_router = bool(interfaces)  # True if dict is not empty, o/w False

        # Remember if router is running before we start smart sync, as it might stop it
        restart_router_after_reset = fwglobals.g.router_api.router_started

        # Finally update configuration.
        # Firstly try smart sync - apply sync-list modifications only.
        # If that fails, go with brutal sync - reset configuration and apply sync-device list
        #
        try:
            # Stop router if needed
            if restart_router:
                reply = fwglobals.g.router_api.call("stop-router")
                if reply['ok'] == 0:
                    raise Exception(" _sync_device: stop-router failed: " + str(reply.get('message')))

            # Update configuration.
            for request in sync_list:
                reply = fwglobals.g.router_api.call(request['message'], request.get('params'))
                if reply['ok'] == 0:
                    raise Exception(" _sync_device: smart sync failed: " + str(reply.get('message')))

            # Start router if needed
            if restart_router:
                reply = fwglobals.g.router_api.call("start-router")
                if reply['ok'] == 0:
                    raise Exception(" _sync_device: start-router failed: " + str(reply.get('message')))

        except Exception as e:
            fwglobals.log.error("FWAGENT_API: _sync_device: smart sync failed: %s" % str(e))
            self._reset_device_soft()
            for request in params['requests']:
                reply = fwglobals.g.router_api.call(request['message'], request.get('params'))
                if reply['ok'] == 0:
                    error = request['message'] + ': ' + str(reply.get('message'))
                    fwglobals.log.error("FWAGENT_API: _sync_device: brutal sync failed: %s" % error)
                    raise Exception(error)
            if restart_router_after_reset:
                fwglobals.g.router_api.call('start-router')
            fwglobals.log.debug("FWAGENT_API: _sync_device: brutal sync succeeded")

        fwglobals.g.router_cfg.reset_signature()
        fwglobals.log.info("FWAGENT_API: _sync_device FINISHED")
        return {'ok': 1}


    def _modify_device(self, params):
        """Handles modify-device request: modifies interfaces, tunnels, routes
        and other configuration entities received within 'modify-device' request.
        To do that this function create pair of 'remove-X' and 'add-X' requests
        for every entity found in the request. Than it forms list of these requests
        where at the first place are located the 'remove-X' requests and after
        them go the 'add-X' requests. The order of 'remove-X' and 'add-X' is
        important, as some configurations entities depends on others. For example,
        the tunnels use interfaces, the routes might use tunnels, etc.
        The order of 'remove-X' is exactly opposite to the order of 'add-X'.

        :param params: Request parameters received from flexiManage:
                        {
                          'modify_router':
                            {
                              'unassign': <list of interfaces that should be removed from VPP>
                              'assign': <list of interfaces that should be added to VPP>
                            }
                          'modify_interfaces':
                            { 'interfaces': <list of interfaces to be modified> }
                          'modify_routes':
                            { 'routes': <list of routes to be modified> }
                          'modify_dhcp_config':
                            { 'dhcp_configs': <list of DHCP servers to be modified> }
                          'modify_app':
                            { 'apps': <list of mulitlink applications to be modified> }
                          'modify_policy':
                            { 'policies': <list of mulitlink policy rules to be modified> }
                        }

        :returns: Dictionary with status code.
        """
        def _modify_device_entity(entities, entity_name):
            add     = []
            remove  = []
            add_req    = 'add-' + entity_name
            remove_req = 'remove-' + entity_name
            for params in entities:
                # Add 'remove-X' request only if entity exists in configuration
                if fwglobals.g.router_cfg.exists(add_req, params):
                    remove.append({ 'message': remove_req, 'params':  params })
                # Add 'add-X' request
                add.append({ 'message': add_req, 'params':  params })
            return (add, remove)

        def _modify_device_router(modify_router_params):
            add     = []
            remove  = []
            for params in modify_router_params.get('unassign', []):
                # Add 'remove-X' request only if entity exists in configuration
                if fwglobals.g.router_cfg.exists('add-interface', params):
                    remove.append({'message': 'remove-interface', 'params': params})
            for params in modify_router_params.get('assign', []):
                add.append({'message': 'remove-interface', 'params': params})
            return (add, remove)

        def _modify_device_routes(entities, entity_name):
            add     = []
            remove  = []
            for params in entities:
                # Add 'remove-X' request only if entity exists in configuration,
                # and only if 'modify-routes' element has 'old_route' parameter.
                if params['old_route']:
                    remove_route_params = {k:v for k,v in params.items() if k != 'new_route'}
                    remove_route_params['via'] = remove_route_params.pop('old_route')
                    if fwglobals.g.router_cfg.exists('add-route', remove_route_params):
                        remove.append({'message': 'remove-route', 'params':  remove_route_params})
                # Add 'add-X' request only if 'modify-routes' element has 'new_route' parameter.
                if params['new_route'] != '':
                    add_route_params = {k:v for k,v in params.items() if k != 'old_route'}
                    add_route_params['via'] = add_route_params.pop('new_route')
                    add.append({'message': 'add-route', 'params':  add_route_params})
            return (add, remove)


        fwglobals.log.info("FWAGENT_API: _modify_device STARTED")

        # Handle inconsistency in section / list / entity names.
        # Order of elements is order of execution of 'add-X' requests.
        #
        sections = [
          ('modify_router',     None,           None),
          ('modify_interfaces', 'interfaces',   'interface'),
          ('modify_routes',     'routes',       'route'),
          ('modify_dhcp_config','dhcp_configs', 'dhcp-config'),
          ('modify_app',        'apps',         'application'),
          ('modify_policy',     'policies',     'multilink-policy')
        ]

        ########################################################################
        # Firstly generate list of 'remove-X' and 'add-X' requests to be executed
        # to modify device configuration out of 'modify-device' data.
        # We call this list the 'modify list'.
        ########################################################################

        list_additions = []
        list_removals  = []

        for (section_name, list_name, entity_name) in sections:
            if section_name in params:
                # 'modify_routes' and 'modify_router' require special handling
                if section_name == 'modify_router':
                    (additions, removals) = _modify_device_router(params[section_name])
                elif section_name == 'modify_routes':
                    (additions, removals) = _modify_device_routes(params[section_name][list_name], entity_name)
                else:
                    (additions, removals) = _modify_device_entity(params[section_name][list_name], entity_name)
                # Update final lists
                list_additions.extend(additions)    # Tail
                list_removals[0:0] = removals       # Head

        # If there are interfaces that are going to be removed during device
        # modification either as part of 'unassign' or 'modify-interface'
        # operations, we have to remove tunnels that use this interfaces.
        # The tunnels will be added back by separate request sent by flexiManage.
        # That means flexiManage is responsible to reconstruct tunnels!
        #
        pci_list = []
        for request in list_removals:
            if request['message'] == 'remove-interface':
                pci_list.append(request['params']['pci'])
        ip_list = fwglobals.g.router_cfg.get_interface_ips(pci_list)
        tunnels = fwglobals.g.router_cfg.get_tunnels()
        remove_tunnel_requests = []
        for t in tunnels:
            if t['src'] in ip_list:
                remove_tunnel_requests.append({
                        'message': 'remove-tunnel',
                        'params' : {'tunnel-id': t['tunnel-id']}
                    })
        if remove_tunnel_requests:
            # 'remove-tunnel'-s should be added right after 'remove-interfaces'.
            # As 'remove-interfaces' should be at the list_removals beginning,
            # it is quite simple to find right location for insertion.
            idx = 0
            for (idx, request) in enumerate(list_removals):
                if request['message'] != 'remove-interface':
                    break
            list_removals[idx:idx] = remove_tunnel_requests


        ########################################################################
        # Now go and modify device configuration.
        # We do that by simulating receiving the aggregated router configuration
        # request, so if one of modification fails the previous will be reverted.
        ########################################################################

        # Restart router is needed, if there interfaces to be assigned to VPP
        # or to be unassigned. The assignment/un-assignment causes modification
        # of the /etc/vpp/startup.conf file, that in turns requires VPP restart.
        #
        should_restart_router = False
        if fwglobals.g.router_cfg.exists('start-router'):
            if 'modify_router' in params:
                if ('assign' in params['modify_router']) or ('unassign' in params['modify_router']):
                    should_restart_router = True

        if should_restart_router:
            fwglobals.g.router_api.call("stop-router")

        # Finally modify device!
        # Note we use fwglobals.g.handle_request() and not the fwglobals.g.router_api.call()
        # in order to enforce update of configuration signature.
        #
        reply = fwglobals.g.handle_request(
            'aggregated-router-api', params={ 'requests': list_removals + list_additions },
            received_msg={ 'message': 'modify-device', 'params': params })

        if should_restart_router:
            fwglobals.g.router_api.call("start-router")

        fwglobals.log.info("FWAGENT_API: _modify_device FINISHED (ok=%d)" % reply['ok'])


        ########################################################################
        # Workaround for following problem:
        # if 'modify-device' request causes change in IP or in GW of WAN interface,
        # the 'remove-interface' part of modification removes GW from the Linux
        # neighbor table, but the consequent 'add-interface' does not add it back.
        # As a result the VPP FIB is stuck with DROP rule for that interface,
        # and traffic on that interface is dropped.
        # The workaround below enforces Linux to update the neighbor table with
        # the latest GW-s. That results in VPPSB to propagate the ARP information
        # into VPP FIB.
        # Note we do this even if 'modify-device' failed, as before failure
        # it might succeed to remove few interfaces.
        ########################################################################
        added_gateways = []
        for request in list_additions:
            if request['message'] == 'add-interface' and \
               request['params'].get('type', '').lower() == 'wan' and \
               request['params'].get('gateway') != None:
                added_gateways.append(request['params']['gateway'])
        if added_gateways:
            # Delay 5 seconds to make sure Linux interfaces were initialized
            time.sleep(5)
            for gw in added_gateways:
                try:
                    cmd = 'ping -c 3 %s' % gw
                    output = subprocess.check_output(cmd, shell=True)
                    fwglobals.log.debug("FWAGENT_API: _modify_device: %s: %s" % (cmd, output))
                except Exception as e:
                    fwglobals.log.debug("FWAGENT_API: _modify_device: %s: %s" % (cmd, str(e)))

        return reply
