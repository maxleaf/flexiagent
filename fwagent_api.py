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
import loadsimulator
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
    'get-device-info':                  '_get_device_info',
    'get-device-stats':                 '_get_device_stats',
    'get-device-logs':                  '_get_device_logs',
    'get-device-packet-traces':         '_get_device_packet_traces',
    'get-device-os-routes':             '_get_device_os_routes',
    'get-router-config':                '_get_router_config',
    'upgrade-device-sw':                '_upgrade_device_sw',
    'reset-device':                     '_reset_device_soft',
    'sync-device':                      '_sync_device',
    'get-wifi-interface-status':        '_get_wifi_interface_status',
    'connect-to-wifi':                  '_connect_to_wifi',
    'lte-perform-operation':            '_lte_perform_operation',
    'wifi-perform-operation':           '_wifi_perform_operation',
    'get-lte-interface-info':           '_get_lte_interface_info',
    'get-wifi-interface-info':          '_get_wifi_interface_info'
}

class FWAGENT_API:
    """This class implements fwagent level APIs of flexiEdge device.
       Typically these APIs are used to monitor various components of flexiEdge.
       They are invoked by the flexiManage over secure WebSocket
       connection using JSON requests.
       For list of available APIs see the 'fwagent_api' variable.
    """
    def call(self, request):
        """Invokes API specified by the 'req' parameter.

        :param request: The request received from flexiManage.

        :returns: Reply.
        """
        req    = request['message']
        params = request.get('params')

        handler = fwagent_api.get(req)
        assert handler, 'fwagent_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwagent_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            if 'readable_errors' in params:
                raise Exception(reply['message'])

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
            info['network']['interfaces'] = fwutils.get_linux_interfaces(cached=False).values()
            info['reconfig'] = '' if loadsimulator.g.enabled() else fwutils.get_reconfig_hash()
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
        reply = {'ok': 1, 'message': configs if configs else []}
        return reply

    def _reset_device_soft(self, params=None):
        """Soft reset device configuration.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        if fwglobals.g.router_api.router_started:
            fwglobals.g.router_api.call({'message':'stop-router'})   # Stop VPP if it runs
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
                          'requests': <list of 'add-X' requests that represent
                                    device configuration stored on flexiManage>
                        }
        :returns: Dictionary with status code.
        """
        fwglobals.log.info("FWAGENT_API: _sync_device STARTED")

        # Go over configuration requests received within sync-device request,
        # intersect them against the requests stored locally and generate new list
        # of remove-X and add-X requests that should take device to configuration
        # received with the sync-device.
        #
        sync_list = fwglobals.g.router_cfg.get_sync_list(params['requests'])
        fwglobals.log.debug("FWAGENT_API: _sync_device: sync-list: %s" % \
                            json.dumps(sync_list, indent=2, sort_keys=True))
        if not sync_list:
            fwglobals.log.info("FWAGENT_API: _sync_device: sync_list is empty, no need to sync")
            fwglobals.g.router_cfg.reset_signature()
            if params.get('type', '') != 'full-sync':
                return {'ok': 1}   # Return if there is no full sync enforcement

        # Finally update configuration.
        # Firstly try smart sync - apply sync-list modifications only.
        # If that fails, go with full sync - reset configuration and apply sync-device list
        #
        if sync_list:
            fwglobals.log.debug("FWAGENT_API: _sync_device: start smart sync")
            sync_request = {
                'message':   'aggregated',
                'params':    { 'requests': sync_list },
                'internals': { 'dont_revert_on_failure': True }
            }
            reply = fwglobals.g.router_api.call(sync_request)

            # If smart sync succeeded and there is no 'full-sync' enforcement
            # in message, finish sync procedure and return.
            # Note today the 'full-sync' enforcement is needed for testing only.
            #
            if reply['ok'] == 1 and params.get('type', '') != 'full-sync':
                fwglobals.g.router_cfg.reset_signature()
                fwglobals.log.debug("FWAGENT_API: _sync_device: smart sync succeeded")
                fwglobals.log.info("FWAGENT_API: _sync_device FINISHED")
                return {'ok': 1}

        # At this point we have to perform full sync.
        # This is due to either smart sync failure or full sync enforcement.
        #
        fwglobals.log.debug("FWAGENT_API: _sync_device: start full sync")
        restart_router = False
        if fwglobals.g.router_api.router_started:
            restart_router = True
            fwglobals.g.router_api.call({'message': 'stop-router'})

        self._reset_device_soft()                       # Wipe out the configuration database
        request = {                                     # Cast 'sync-device' to 'aggregated'
            'message':   'aggregated',
            'params':    { 'requests': params['requests'] },
            'internals': { 'dont_revert_on_failure': True }
        }
        reply = fwglobals.g.router_api.call(request)    # Apply finally the received configuration
        if reply['ok'] == 0:
            raise Exception(" _sync_device: full sync failed: " + str(reply.get('message')))

        if restart_router:
            fwglobals.g.router_api.call({'message': 'start-router'})
        fwglobals.log.debug("FWAGENT_API: _sync_device: full sync succeeded")

        fwglobals.g.router_cfg.reset_signature()
        fwglobals.log.info("FWAGENT_API: _sync_device FINISHED")
        return {'ok': 1}

    def _get_wifi_interface_status(self, params):
        fwglobals.log.info("FWAGENT_API: _get_wifi_interface_status STARTED")

        if fwutils.is_wifi_interface(params['dev_id']):
            try:
                networks = fwutils.wifi_get_available_networks(params['dev_id'])

                interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])
                addr = fwutils.get_interface_address(interface_name)
                connectivity = os.system("ping -c 1 -W 5 -I %s 8.8.8.8 > /dev/null 2>&1" % interface_name) == 0

                response = {
                    'address':      addr,
                    'networks':     networks,
                    'connectivity': connectivity
                }

                fwglobals.log.info("FWAGENT_API: _get_wifi_interface_status FINISHED")
                return {'message': response, 'ok': 1}
            except:
                raise Exception("_get_wifi_interface_status: failed to get available access points: %s" % format(sys.exc_info()[1]))

        return {'message': 'This interface is not WIFI', 'ok': 0}

    def _connect_to_wifi(self, params):
        try:
            result = fwutils.connect_to_wifi(params)

            if result:
                fwglobals.log.info("FWAGENT_API: _connect_to_wifi FINISHED")
                return {'message': result, 'ok': result}

            return {'message': False, 'ok': 0}
        except:
            raise Exception("_connect_to_wifi: failed to connect to wifi: %s" % format(sys.exc_info()[1]))

    def _wifi_perform_operation(self, params):
        try:
            operation = params['operation'] if 'operation' in params else None
            if not operation:
                return (False, 'This interface is not WIFI')

            if fwutils.is_wifi_interface(params['dev_id']) == False:
                return (False, 'This interface is not a WIFI interface')

            if operation == 'start':
                is_success, error = self._wifi_start_ap(params)
            elif operation == 'stop':
                is_success, error = self._wifi_stop_ap(params)
            else:
                is_success, error = (False, 'No supported operation was requested')

            return {'message': error, 'ok': is_success}
        except Exception as e:
            raise Exception("_wifi_perform_operation: failed. %s" % str(e))

    def _wifi_start_ap(self, params):
        try:
            fwutils.configure_hostapd(params['dev_id'], params['configuration'])
            is_success, error =  fwutils.start_hostapd()

            return is_success, error
        except Exception as e:
            raise Exception("_wifi_start_ap: failed to start wifi access point: %s" % str(e))


    def _wifi_stop_ap(self, params):
        try:
            is_assigned = fwglobals.g.router_cfg.get_interfaces(dev_id=params['dev_id'])
            if fwutils.vpp_does_run() and is_assigned:
                return (False, 'Please unassigned this interface in order to stop the Access Point')

            is_success, error = fwutils.stop_hostapd()
            os.system('ifconfig wlan0 0')

            return is_success, error
        except Exception as e:
            raise Exception("_wifi_stop_ap: failed to stop wifi access point: %s" % str(e))

    def _get_wifi_interface_info(self, params):
        try:
            interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])
            ap_status = fwutils.pid_of('hostapd')

            clients = fwutils.wifi_ap_get_clients(interface_name)

            response = {
                'clients'             : clients,
                'ap_status'           : ap_status != None
            }

            return {'message': response, 'ok': 1}
        except Exception as e:
            raise Exception("_get_lte_interface_status: %s" % str(e))

    def _lte_perform_operation(self, params):
        try:
            operation = params['operation'] if 'operation' in params else None
            if not operation:
                raise Exception("Operation was not specified")

            if fwutils.is_lte_interface(params['dev_id']) == False:
                return (False, 'This interface is not LTE')

            if operation == 'connect':
                is_success, error = self._connect_to_lte(params)
            elif operation == 'disconnect':
                is_success, error = self._disconnect_from_lte(params)
            else:
                is_success, error = (False, 'No supported operation was requested')

            return {'message': error, 'ok': is_success}
        except Exception as e:
            raise Exception("_lte_perform_operation: failed. %s" % str(e))

    def _disconnect_from_lte(self, params):
        try:
            # don't perform disconnect if this interface is already assigned to vpp and vpp is run
            is_assigned = fwglobals.g.router_cfg.get_interfaces(dev_id=params['dev_id'])
            if fwutils.vpp_does_run() and is_assigned:
                return (False, 'Please unassigned this interface in order to disconnect LTE ')

            is_success, error = fwutils.lte_disconnect()
            os.system('ifconfig wwan0 0')

            return is_success, error
        except Exception as e:
            raise Exception("_disconnect_from_lte: failed to disconnect from lte: %s" % str(e))


    def _connect_to_lte(self, params):
        try:
            apn = params['apn'] if 'apn' in params else ''
            is_success, error =  fwutils.lte_connect(apn, params['dev_id'])

            if is_success:
                fwutils.set_lte_info_on_linux_interface()

            return is_success, error
        except Exception as e:
            raise Exception("_connect_to_lte: failed to connect to lte: %s" % str(e))

    def _get_lte_interface_info(self, params):
        try:
            interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])

            sim_status = fwutils.lte_sim_status()
            signals = fwutils.lte_get_radio_signals_state()
            hardware_info = fwutils.lte_get_hardware_info()
            connection_state = fwutils.lte_get_connection_state()
            packet_service_state = fwutils.lte_get_packets_state()
            system_info = fwutils.lte_get_system_info()

            is_assigned = fwglobals.g.router_cfg.get_interfaces(dev_id=params['dev_id'])
            if fwutils.vpp_does_run() and is_assigned:
                interface_name = fwutils.dev_id_to_tap(params['dev_id'])

            addr = fwutils.get_interface_address(interface_name)
            connectivity = os.system("ping -c 1 -W 1 -I %s 8.8.8.8 > /dev/null 2>&1" % interface_name) == 0

            response = {
                'address'             : addr,
                'signals'             : signals,
                'connection_state'    : connection_state,
                'connectivity'        : connectivity,
                'packet_service_state': packet_service_state,
                'hardware_info'       : hardware_info,
                'system_info'         : system_info,
                'sim_status'          : sim_status
            }

            return {'message': response, 'ok': 1}
        except Exception as e:
            raise Exception("_get_lte_interface_status: %s" % str(e))

