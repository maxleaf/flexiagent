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
import re
from pyroute2 import IPDB
ipdb = IPDB()

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
    'reset-device':                  '_reset_device_soft',
    'sync-device':                   '_sync_device',
    'upgrade-device-sw':             '_upgrade_device_sw',
}

class LTE_ERROR_MESSAGES():
    PIN_IS_WRONG = 'PIN_IS_WRONG'
    PIN_IS_REQUIRED = 'PIN_IS_REQUIRED'
    PIN_IS_DISABLED = 'PIN_IS_DISABLED'

    NEW_PIN_IS_REQUIRED = 'NEW_PIN_IS_REQUIRED'

    PUK_IS_WRONG = 'PUK_IS_WRONG'
    PUK_IS_REQUIRED = 'PUK_IS_REQUIRED'

routes_protocol_map = {
    -1: '',
    0: 'unspec',
    1: 'redirect',
    2: 'kernel',
    3: 'boot',
    4: 'static',
    8: 'gated',
    9: 'ra',
    10: 'mrt',
    11: 'zebra',
    12: 'bird',
    13: 'dnrouted',
    14: 'xorp',
    15: 'ntk',
    16: 'dhcp',
    18: 'keepalived',
    42: 'babel',
    186: 'bgp',
    187: 'isis',
    188: 'ospf',
    189: 'rip',
    192: 'eigrp',
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
            if fwglobals.g.ikev2.is_private_key_created():
                info['ikev2'] = fwglobals.g.ikev2.get_certificate_expiration()
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
    	    'application_ids': fwglobals.g.APPLICATION_IDS_LOG_FILE,
    	    'syslog': fwglobals.g.SYSLOG_FILE,
            'dhcp': fwglobals.g.DHCP_LOG_FILE,
            'vpp': fwglobals.g.VPP_LOG_FILE,
            'ospf': fwglobals.g.OSPF_LOG_FILE,
            'open-vpn': fwglobals.g.OPENVPN_LOG_FILE,
            'hostapd': fwglobals.g.HOSTAPD_LOG_FILE,
            'agentui': fwglobals.g.AGENT_UI_LOG_FILE,
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

        route_entries = []

        for route in ipdb.routes:
            try:
                dst = route.dst
                if dst == 'default':
                    dst = '0.0.0.0/0'

                metric = route.priority
                protocol = routes_protocol_map[route.get('proto', -1)]

                if not route.multipath:
                    gateway = route.gateway
                    interface = ipdb.interfaces[route.oif].ifname

                    route_entries.append({
                        'destination': dst,
                        'gateway': gateway,
                        'metric': metric,
                        'interface': interface,
                        'protocol': protocol
                    })
                else:
                    for path in route.multipath:
                        gateway = path.gateway
                        interface = ipdb.interfaces[path.oif].ifname

                        route_entries.append({
                            'destination': dst,
                            'gateway': gateway,
                            'metric': metric,
                            'interface': interface,
                            'protocol': protocol
                        })
            except Exception as e:
                fwglobals.log.error("_get_device_os_routes: failed to parse route %s.\nroutes=%s." % \
                    (str(route), str(ip.routes)))
                pass

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
            fwglobals.g.handle_request({'message':'stop-router'})   # Stop VPP if it runs
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

        # Check that all messages are supported
        non_supported_messages = list([x for x in params['requests'] if x['message'] not in fwglobals.request_handlers])
        if non_supported_messages:
            raise Exception("_sync_device: unsupported requests found: %s" % str(non_supported_messages))

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
        try:
            interface_name = fwutils.dev_id_to_linux_if(params['dev_id'])

            sim_status = fwutils.lte_sim_status(params['dev_id'])
            signals = fwutils.lte_get_radio_signals_state(params['dev_id'])
            hardware_info, _ = fwutils.lte_get_hardware_info(params['dev_id'])
            packet_service_state = fwutils.lte_get_packets_state(params['dev_id'])
            system_info = fwutils.lte_get_system_info(params['dev_id'])
            default_settings = fwutils.lte_get_default_settings(params['dev_id'])
            phone_number = fwutils.lte_get_phone_number(params['dev_id'])
            pin_state = fwutils.lte_get_pin_state(params['dev_id'])
            connection_state = fwutils.mbim_connection_state(params['dev_id'])
            registration_network = fwutils.mbim_registration_state(params['dev_id'])

            tap_name = fwutils.dev_id_to_tap(params['dev_id'], check_vpp_state=True)
            if tap_name:
                interface_name = tap_name

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
                'pin_state'           : pin_state,
                'connection_state'    : connection_state,
                'registration_network': registration_network
            }
            return {'message': response, 'ok': 1}
        except Exception as e:
            fwglobals.log.error('Failed to get LTE information. %s' % str(e))
            return {'message': str(e), 'ok': 0}

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

    def _handle_unblock_sim(self, params):
        dev_id = params['dev_id']
        puk = params.get('puk')
        new_pin = params.get('newPin')

        if not puk:
            raise Exception(LTE_ERROR_MESSAGES.PUK_IS_REQUIRED)

        if not new_pin:
            raise Exception(LTE_ERROR_MESSAGES.NEW_PIN_IS_REQUIRED)

        # unblock the sim and get the updated status
        updated_status = fwutils.qmi_unblocked_pin(dev_id, puk, new_pin)
        updated_pin_state = updated_status.get('PIN1_STATUS')

        # if SIM status is not one of below statuses, it means that puk code is wrong
        if updated_pin_state not in['disabled', 'enabled-verified']:
            raise Exception(LTE_ERROR_MESSAGES.PUK_IS_WRONG)

    def _handle_change_pin_status(self, params):
        dev_id = params['dev_id']
        current_pin = params.get('currentPin')
        enable = params.get('enable', False)

        updated_status, err = fwutils.qmi_set_pin_protection(dev_id, current_pin, enable)
        if err:
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is verified so we reset wrong pin protection
        fwutils.set_lte_db_entry(dev_id, 'wrong_pin', None)

    def _handle_change_pin_code(self, params, is_currently_enabled):
        dev_id = params['dev_id']
        current_pin = params.get('currentPin')
        new_pin = params.get('newPin')

        if not is_currently_enabled: # can't change disabled pin
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_DISABLED)
        updated_status, err = fwutils.qmi_change_pin(dev_id, current_pin, new_pin)
        if err:
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is changed so we reset wrong pin protection
        fwutils.set_lte_db_entry(dev_id, 'wrong_pin', None)

    def _handle_verify_pin_code(self, params, is_currently_enabled, retries_left):
        dev_id = params['dev_id']
        current_pin = params.get('currentPin')

        updated_status, err = fwutils.qmi_verify_pin(dev_id, current_pin)
        if err and not is_currently_enabled: # can't verify disabled pin
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_DISABLED)
        if err:
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

        updated_pin_state = updated_status.get('PIN1_STATUS')
        updated_retries_left = updated_status.get('PIN1_RETRIES', '3')
        if updated_retries_left != '3' and int(retries_left) > int(updated_retries_left):
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)
        if updated_pin_state not in['disabled', 'enabled-verified']:
            raise Exception(LTE_ERROR_MESSAGES.PIN_IS_WRONG)

        # at this point, pin is verified so we reset wrong pin protection
        fwutils.set_lte_db_entry(dev_id, 'wrong_pin', None)

    def _modify_lte_pin(self, params):
        try:
            dev_id = params['dev_id']
            new_pin = params.get('newPin')
            current_pin = params.get('currentPin')
            enable = params.get('enable', False)

            current_pin_state = fwutils.lte_get_pin_state(dev_id)
            is_currently_enabled = current_pin_state.get('PIN1_STATUS') != 'disabled'
            retries_left = current_pin_state.get('PIN1_RETRIES', '3')

            # Handle blocked SIM card. In order to unblock it a user should provide PUK code and new PIN code
            if current_pin_state.get('PIN1_STATUS') == 'blocked' or retries_left == '0':
                self._handle_unblock_sim(params)
                return {'ok': 1, 'message': { 'err_msg': None, 'data': fwutils.lte_get_pin_state(dev_id)}}

            # for the following operations we need current pin
            if not current_pin:
                raise Exception(LTE_ERROR_MESSAGES.PIN_IS_REQUIRED)

            need_to_verify = True
            # check if need to enable/disable PIN
            if is_currently_enabled != enable:
                self._handle_change_pin_status(params)
                need_to_verify = False

            # check if need to change PIN
            if new_pin and new_pin != current_pin:
                self._handle_change_pin_code(params, is_currently_enabled)
                need_to_verify = False

            # verify PIN if no other change requested by the user.
            # no need to verify if we enabled or disabled the pin since it's already verified
            if need_to_verify:
                self._handle_verify_pin_code(params, is_currently_enabled, retries_left)

            reply = {'ok': 1, 'message': { 'err_msg': None, 'data': fwutils.lte_get_pin_state(dev_id)}}
        except Exception as e:
            reply = {'ok': 0, 'message': { 'err_msg': str(e), 'data': fwutils.lte_get_pin_state(dev_id)} }
        return reply

    def _get_device_certificate(self, params):
        """IKEv2 certificate generation.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with status code.
        """
        return fwglobals.g.ikev2.create_private_key(params['days'], params['new'])
