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
from shutil import copyfile
import fwglobals
import fwstats
import fwutils
import fwsystem_api

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
    # WiFi jobs
    'wifi-perform-operation':           '_wifi_perform_operation',
    'wifi-get-interface-info':          '_wifi_get_interface_info',
    # LTE jobs
    'lte-get-interface-info':           '_lte_get_interface_info',
    'lte-reset':                        '_lte_reset'
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
        system_configs = fwutils.dump_system_config()
        configs += system_configs
        reply = {'ok': 1, 'message': configs if configs else []}
        return reply

    def _reset_device_soft(self, params=None):
        """Soft reset device configuration.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        if fwglobals.g.router_api.state_is_started():
            fwglobals.g.router_api.call({'message':'stop-router'})   # Stop VPP if it runs
        fwutils.reset_router_config()
        return {'ok': 1}

    def _full_sync(self, router_sync_list, system_sync_list):
        fwglobals.log.debug("_sync_device: start full sync")
        
        if router_requests or system_sync_list:
            self._reset_device_soft()

        if system_sync_list:
            for sys_request in system_sync_list:
                reply = fwglobals.g.system_api.call(sys_request)
                if reply['ok'] == 0:
                    raise Exception(" _sync_device: system full sync failed: " + str(reply.get('message')))

        if router_sync_list:
            restart_router = False
            if fwglobals.g.router_api.state_is_started():
                restart_router = True
                fwglobals.g.router_api.call({'message': 'stop-router'})

            request = {     # Cast 'sync-device' to 'aggregated'
                'message':   'aggregated',
                'params':    { 'requests': router_requests },
                'internals': { 'dont_revert_on_failure': True }
            }

            reply = fwglobals.g.router_api.call(request)    # Apply finally the received configuration
            
            if reply['ok'] == 0:
                raise Exception(" _sync_device: router full sync failed: " + str(reply.get('message')))

            if restart_router:
                fwglobals.g.router_api.call({'message': 'start-router'})

            fwglobals.log.debug("_sync_device: router full sync succeeded")
            fwglobals.g.router_cfg.reset_signature()


        fwglobals.log.info("_sync_device FINISHED")
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
        fwglobals.log.info("_sync_device STARTED")

        # Go through all the requests and check 
        # which ones belong to the router and which ones belong to the agent_api
        router_requests = []
        system_requests = []
        for request in params['requests']:
            if request['message'] in fwsystem_api.fwsystem_translators:
                system_requests.append(request)
            else:
                router_requests.append(request)

        # Go over configuration requests received within sync-device request,
        # intersect them against the requests stored locally and generate new list
        # of remove-X and add-X requests that should take device to configuration
        # received with the sync-device.
        #
        router_sync_list = fwglobals.g.router_cfg.get_sync_list(router_requests)
        system_sync_list = fwglobals.g.system_cfg.get_sync_list(system_requests)
        
        fwglobals.log.debug("_sync_device: router-sync-list: %s" % \
                            json.dumps(router_sync_list, indent=2, sort_keys=True))
        fwglobals.log.debug("_sync_device: system-sync-list: %s" % \
                            json.dumps(system_sync_list, indent=2, sort_keys=True))
                            
        if not system_sync_list and not router_sync_list:
            fwglobals.log.info("_sync_device: sync_list is empty, no need to sync")
            fwglobals.g.router_cfg.reset_signature()
            fwglobals.g.system_cfg.reset_signature()
            if params.get('type', '') != 'full-sync':
                return {'ok': 1}   # Return if there is no full sync enforcement

        # Finally update configuration.
        # Firstly try smart sync - apply sync-list modifications only.
        # If that fails, go with full sync - reset configuration and apply sync-device list
        # Note today the 'full-sync' enforcement is needed for testing only.

        if params.get('type', '') == 'full-sync':
            return self._full_sync(router_sync_list, system_sync_list)

        succeeded = True
        if system_sync_list:
            fwglobals.log.debug("_sync_device: start system smart sync")
            
            for sys_request in system_sync_list:
                reply = fwglobals.g.system_api.call(sys_request)
                if reply['ok'] == 0:
                    succeeded = False
                    break
            
            if succeeded:
                fwglobals.g.system_cfg.reset_signature()
                fwglobals.log.debug("_sync_device: system smart sync succeeded")

        if succeeded and router_sync_list:
            fwglobals.log.debug("_sync_device: start router smart sync")
            sync_request = {
                'message':   'aggregated',
                'params':    { 'requests': router_sync_list },
                'internals': { 'dont_revert_on_failure': True }
            }
            reply = fwglobals.g.router_api.call(sync_request)

            # If smart sync succeeded and there is no 'full-sync' enforcement
            # in message, finish sync procedure and return.
            # Note today the 'full-sync' enforcement is needed for testing only.
            #
            if reply['ok'] == 1 and params.get('type', '') != 'full-sync':
                fwglobals.g.router_cfg.reset_signature()
                fwglobals.log.debug("_sync_device: router smart sync succeeded")  
            else:
                succeeded = False

        if succeeded:
            fwglobals.log.info("_sync_device FINISHED")    
            return {'ok': 1}

        # At this point we have to perform full sync due mart sync failure.
        return self._full_sync(router_sync_list, system_sync_list)

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

            inf_name = fwutils.dev_id_to_linux_if(params['dev_id'])
            os.system('ifconfig %s 0' % inf_name)

            return is_success, error
        except Exception as e:
            raise Exception("_wifi_stop_ap: failed to stop wifi access point: %s" % str(e))

    def _wifi_get_interface_info(self, params):
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
            raise Exception("_wifi_get_interface_info: %s" % str(e))

    def _lte_get_interface_info(self, params):
        try:
            interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])

            sim_status = fwutils.lte_sim_status(params['dev_id'])
            signals = fwutils.lte_get_radio_signals_state(params['dev_id'])
            hardware_info = fwutils.lte_get_hardware_info(params['dev_id'])
            connection_state = fwutils.lte_get_connection_state(params['dev_id'])
            packet_service_state = fwutils.lte_get_packets_state(params['dev_id'])
            system_info = fwutils.lte_get_system_info(params['dev_id'])
            default_apn = fwutils.lte_get_default_apn(params['dev_id'])

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
                'sim_status'          : sim_status,
                'default_apn'         : default_apn
            }

            return {'message': response, 'ok': 1}
        except Exception as e:
            raise Exception("_get_lte_interface_status: %s" % str(e))

    def _lte_reset(self, params):
        """Rest LTE modem card.
        
        :param params: Parameters to use.

        :returns: Dictionary status code.
        """
        try:
            # don't perform reset if interface is already assigned to vpp and vpp is run
            is_assigned = fwglobals.g.router_cfg.get_interfaces(dev_id=params['dev_id'])
            if fwutils.vpp_does_run() and is_assigned:
                return {'ok': 0, 'message': 'Please unassigned this interface in order to reset the LTE card'}

            is_success, error = fwutils.lte_disconnect(params['dev_id'], True)
            fwutils.qmi_sim_power_off(params['dev_id'])
            fwutils.qmi_sim_power_on(params['dev_id'])

            reply = {'ok': 1, 'message': ''}
        except Exception as e:
            reply = {'ok': 0, 'message': str(e)}

        return reply
