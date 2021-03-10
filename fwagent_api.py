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
import subprocess
import os
from shutil import copyfile
import fwglobals
import fwikev2
import fwstats
import fwutils
import fwsystem_api
import fwrouter_api

fwagent_api = {
    'get-device-certificate':        '_get_device_certificate',
    'get-device-config':             '_get_device_config',
    'get-device-info':               '_get_device_info',
    'get-device-logs':               '_get_device_logs',
    'get-device-os-routes':          '_get_device_os_routes',
    'get-device-packet-traces':      '_get_device_packet_traces',
    'get-device-stats':              '_get_device_stats',
    'get-lte-info':                  '_get_lte_info',
    'get-wifi-info':                 '_get_wifi_info',
    'modify-lte-pin':                '_modify_lte_pin',
    'reset-lte':                     '_reset_lte',
    'sync-device':                   '_sync_device',
    'upgrade-device-sw':             '_upgrade_device_sw',
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
                    key1 = ""
                    key2 = ""
                    key3 = ""
                    key4 = ""
                    if "ipsec" in params:
                        key1 = params["ipsec"]["local-sa"]["crypto-key"]
                        key2 = params["ipsec"]["local-sa"]["integr-key"]
                        key3 = params["ipsec"]["remote-sa"]["crypto-key"]
                        key4 = params["ipsec"]["remote-sa"]["integr-key"]
                    tunnel_info.append({
                        "id": str(tunnel_id),
                        "key1": key1,
                        "key2": key2,
                        "key3": key3,
                        "key4": key4
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
            info['network']['interfaces'] = list(fwutils.get_linux_interfaces(cached=False).values())
            info['reconfig'] = '' if loadsimulator.g.enabled() else fwutils.get_reconfig_hash()
            info['ikev2'] = '' if loadsimulator.g.enabled() else fwglobals.g.ikev2.get_certificate_expiration()
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
            'hostapd': fwglobals.g.HOSTAPD_LOG_FILE,
            'agentui': fwglobals.g.AGNET_UI_LOG_FILE
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

    def _get_device_config(self, params):
        """Get device configuration from DB.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with configuration and status code.
        """
        router_config = fwutils.dump_router_config()
        system_config = fwutils.dump_system_config()
        config = router_config + system_config
        reply = {'ok': 1, 'message': config if config else []}
        return reply

    def _reset_device_soft(self, params=None):
        """Soft reset device configuration.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        if fwglobals.g.router_api.state_is_started():
            fwglobals.g.router_api.call({'message':'stop-router'})   # Stop VPP if it runs
        fwutils.reset_device_config()
        return {'ok': 1}

    def _sync_device(self, params):
        """Handles the 'sync-device' request: synchronizes device configuration
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

        full_sync_enforced = params.get('type', '') == 'full-sync'

        for module_name, module in list(fwglobals.modules.items()):
            if module.get('sync', False) == True:
                # get api module. e.g router_api, system_api
                api_module = getattr(fwglobals.g, module.get('object'))
                api_module.sync(params['requests'], full_sync_enforced)

        # At this point the sync succeeded.
        # In case of failure - exception is raised by sync()
        fwutils.reset_device_config_signature()
        fwglobals.log.info("_sync_device FINISHED")
        return {'ok': 1}

    def _get_wifi_info(self, params):
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
            raise Exception("_get_wifi_info: %s" % str(e))

    def _get_lte_info(self, params):
        interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])

        sim_status = fwutils.lte_sim_status(params['dev_id'])
        signals = fwutils.lte_get_radio_signals_state(params['dev_id'])
        hardware_info = fwutils.lte_get_hardware_info(params['dev_id'])
        packet_service_state = fwutils.lte_get_packets_state(params['dev_id'])
        system_info = fwutils.lte_get_system_info(params['dev_id'])
        default_settings = fwutils.lte_get_default_settings(params['dev_id'])
        phone_number = fwutils.lte_get_phone_number(params['dev_id'])
        pin_state = fwutils.lte_get_pin_state(params['dev_id'])

        is_assigned = fwutils.is_interface_assigned_to_vpp(params['dev_id'])
        if fwutils.vpp_does_run() and is_assigned:
            interface_name = fwutils.dev_id_to_tap(params['dev_id'])

        addr = fwutils.get_interface_address(interface_name)
        connectivity = os.system("ping -c 1 -W 1 -I %s 8.8.8.8 > /dev/null 2>&1" % interface_name) == 0

        response = {
            'address'             : addr,
            'signals'             : signals,
            'connectivity'        : connectivity,
            'packet_service_state': packet_service_state,
            'hardware_info'       : hardware_info,
            'system_info'         : system_info,
            'sim_status'          : sim_status,
            'default_settings'    : default_settings,
            'phone_number'        : phone_number,
            'pin_state'           : pin_state
        }

        return {'message': response, 'ok': 1}


    def _reset_lte(self, params):
        """Reset LTE modem card.

        :param params: Parameters to use.

        :returns: Dictionary status code.
        """
        try:
            fwutils.reset_modem(params['dev_id'])

            # restore lte connection if needed
            fwglobals.g.system_api.restore_configuration(types=['add-lte'])

            reply = {'ok': 1, 'message': ''}
        except Exception as e:
            reply = {'ok': 0, 'message': str(e)}
        return reply

    def _modify_lte_pin(self, params):
        try:
            dev_id = params['dev_id']
            new_pin = params.get('newPin')
            current_pin = params.get('currentPin')
            enable = params.get('enable', False)
            puk = params.get('puk')

            current_pin_state = fwutils.lte_get_pin_state(dev_id)
            is_currently_enabled = current_pin_state.get('PIN1_STATUS') != 'disabled'
            retries_left = current_pin_state.get('PIN1_RETRIES', '3')

            # check if blocked and puk isn't provided
            if retries_left == '0' and not puk:
                return {'ok': 0, 'message': 'The PIN is locked. Please unblocked it with PUK code'}

            if current_pin_state.get('PIN1_STATUS') == 'blocked':
                if not puk or not new_pin:
                    return {'ok': 0, 'message': 'The PIN is locked. Please provide PUK code and new PIN number'}
                # unblock
                updated_status = fwutils.qmi_unblocked_pin(dev_id, puk, new_pin)
                updated_pin_state = updated_status.get('PIN1_STATUS')
                if updated_pin_state not in['disabled', 'enabled-verified']:
                    return {'ok': 0, 'message': 'PUK is wrong'}

                return {'ok': 1, 'message': ''}

            if not current_pin:
                return {'ok': 0, 'message': 'PIN is required'}

            # verify pin first
            updated_status = fwutils.qmi_verify_pin(dev_id, current_pin)
            updated_pin_state = updated_status.get('PIN1_STATUS')
            updated_retries_left = updated_status.get('PIN1_RETRIES', 3)
            if updated_retries_left != '3' and retries_left != updated_retries_left:
                return {'ok': 0, 'message': 'PIN is wrong'}
            if updated_pin_state not in['disabled', 'enabled-verified']:
                return {'ok': 0, 'message': 'PIN is wrong'}

            # check if need to enable/disable
            if is_currently_enabled != enable:
                fwutils.qmi_set_pin_protection(dev_id, current_pin, enable)

            # check if need to change
            if new_pin and new_pin != current_pin:
                fwutils.qmi_change_pin(dev_id, current_pin, new_pin)

            reply = {'ok': 1, 'message': ''}
        except Exception as e:
            reply = {'ok': 0, 'message': str(e)}
        return reply

    def _get_device_certificate(self, params):
        """IKEv2 certificate generation.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        return fwglobals.g.ikev2.create_private_key(params['days'])
