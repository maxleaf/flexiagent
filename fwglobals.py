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
import Pyro4
import re
import time
import traceback
import yaml

from fwrouter_api import FWROUTER_API
from fwagent_api import FWAGENT_API
from os_api import OS_API
from fwlog import Fwlog
from fwapplications_api import FwApps
from fwpolicies_api import FwPolicies

modules = {
    'fwagent_api':  __import__('fwagent_api'),
    'fwapps_api':   __import__('fwapplications_api'),
    'fwpolicy_api': __import__('fwpolicies_api'),
    'fwrouter_api': __import__('fwrouter_api'),
    'os_api':       __import__('os_api'),
}

request_handlers = {

    ##############################################################
    # DEVICE API-s
    # ------------------------------------------------------------
    # These API-s implement interface between FlexiEdge device
    # and FlexiManage server. The device API-s are invoked using
    # requests sent by server to device over secured connection.
    ##############################################################

    # Agent API
    'get-device-info':              '_call_agent_api',
    'get-device-stats':             '_call_agent_api',
    'get-device-logs':              '_call_agent_api',
    'get-device-packet-traces':     '_call_agent_api',
    'get-device-os-routes':         '_call_agent_api',
    'get-router-config':            '_call_agent_api',
    'upgrade-device-sw':            '_call_agent_api',
    'reset-device':                 '_call_agent_api',
    'sync-device':                  '_call_agent_api',

    # Applications API
    'add-app-info':                 '_call_apps_api',
    'remove-app-info':              '_call_apps_api',

    # Policy API
    'add-policy-info':              '_call_policy_api',
    'remove-policy-info':           '_call_policy_api',

    # Router API
    'aggregated-router-api':        '_call_router_api',
    'start-router':                 '_call_router_api',
    'stop-router':                  '_call_router_api',
    'add-interface':                '_call_router_api',
    'remove-interface':             '_call_router_api',
    'add-route':                    '_call_router_api',
    'remove-route':                 '_call_router_api',
    'add-tunnel':                   '_call_router_api',
    'remove-tunnel':                '_call_router_api',
    'modify-device':                '_call_router_api',
    'add-dhcp-config':              '_call_router_api',
    'remove-dhcp-config':           '_call_router_api',
    'add-application':              '_call_router_api',
    'remove-application':           '_call_router_api',
    'add-multilink-policy':        '_call_router_api',
    'remove-multilink-policy':     '_call_router_api',

    ##############################################################
    # INTERNAL API-s
    # ------------------------------------------------------------
    # These API-s are invoked locally by handlers of server
    # requests, e.g. by FWROUTER_API module.
    # The FWROUTER_API module translates received requests
    # into lists of commands that might be not executed immediately.
    # These internal commands represent the INTERNAL API-s
    # listed below. They are recorded into database and are invoked
    # later, when router is started.
    ##############################################################

    # OS API
    'interfaces':                   '_call_os_api',
    'cpuutil':                      '_call_os_api',
    'exec':                         '_call_os_api',
    'savefile':                     '_call_os_api',
    'pcisub':                       '_call_os_api',
    'tapsub':                       '_call_os_api',
    'gresub':                       '_call_os_api',
    'ifcount':                      '_call_os_api',
    'ifstats':                      '_call_os_api',
    'stop_router':                  '_call_os_api',
    'connect_to_router':            '_call_os_api',
    'disconnect_from_router':       '_call_os_api',

    # VPP API
    'abf_itf_attach_add_del':       '_call_vpp_api',
    'abf_policy_add_del':           '_call_vpp_api',
    'acl_add_replace':              '_call_vpp_api',
    'acl_del':                      '_call_vpp_api',
    'bridge_domain_add_del':        '_call_vpp_api',
    'create_loopback_instance':     '_call_vpp_api',
    'delete_loopback':              '_call_vpp_api',
    'ipsec_gre_add_del_tunnel':     '_call_vpp_api',
    'ipsec_sad_add_del_entry':      '_call_vpp_api',
    'ipsec_spd_add_del':            '_call_vpp_api',
    'ipsec_interface_add_del_spd':  '_call_vpp_api',
    'ipsec_spd_add_del_entry':      '_call_vpp_api',
    'l2_flags':                     '_call_vpp_api',
    'nat44_add_del_interface_addr':             '_call_vpp_api',
    'nat44_interface_add_del_output_feature':   '_call_vpp_api',
    'nat44_forwarding_enable_disable':          '_call_vpp_api',
    'nat44_add_del_identity_mapping':           '_call_vpp_api',
    'sw_interface_add_del_address': '_call_vpp_api',
    'sw_interface_set_flags':       '_call_vpp_api',
    'sw_interface_set_l2_bridge':   '_call_vpp_api',
    'sw_interface_set_mac_address': '_call_vpp_api',
    'sw_interface_set_mtu':         '_call_vpp_api',
    'vmxnet3_create':               '_call_vpp_api',
    'vmxnet3_delete':               '_call_vpp_api',
    'vxlan_add_del_tunnel':         '_call_vpp_api',

    # Python API
    'python':                       '_call_python_api',
    'python-kwargs':                '_call_python_kwargs_api'
}

global g_initialized
g_initialized = False

@Pyro4.expose
class Fwglobals:
    """This is global data class representation.

    """
    class FwConfiguration:
        """This is configuration class representation.

        :param filename:    YAML configuration file name.
        :param data_path:   Path to token file.
        """
        def __init__(self, filename, data_path):
            """Constructor method
            """
            global log
            DEFAULT_BYPASS_CERT    = False
            DEFAULT_DEBUG          = False
            DEFAULT_MANAGEMENT_URL = 'https://app.flexiwan.com:443'
            DEFAULT_TOKEN_FILE     = data_path + 'token.txt'
            DEFAULT_UUID           = None
            try:
                with open(filename, 'r') as conf_file:
                    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
                agent_conf = conf.get('agent', {})
                self.BYPASS_CERT    = agent_conf.get('bypass_certificate', DEFAULT_BYPASS_CERT)
                self.DEBUG          = agent_conf.get('debug',  DEFAULT_DEBUG)
                self.MANAGEMENT_URL = agent_conf.get('server', DEFAULT_MANAGEMENT_URL)
                self.TOKEN_FILE     = agent_conf.get('token',  DEFAULT_TOKEN_FILE)
                self.UUID           = agent_conf.get('uuid',   DEFAULT_UUID)
            except Exception as e:
                log.excep("FwConfiguration: %s, set defaults" % str(e))
                self.BYPASS_CERT    = DEFAULT_BYPASS_CERT
                self.DEBUG          = DEFAULT_DEBUG
                self.MANAGEMENT_URL = DEFAULT_MANAGEMENT_URL
                self.TOKEN_FILE     = DEFAULT_TOKEN_FILE
                self.UUID           = DEFAULT_UUID
            if self.DEBUG:
                log.set_level(Fwlog.FWLOG_LEVEL_DEBUG)

    def __init__(self):
        """Constructor method
        """
        # Set default configuration
        self.NUM_RETRIES_ALLOWED = 3
        self.RETRY_INTERVAL_MIN  = 5 # seconds - is used for both registration and main connection
        self.RETRY_INTERVAL_MAX  = 15
        self.RETRY_INTERVAL_LONG_MIN = 50
        self.RETRY_INTERVAL_LONG_MAX = 70
        self.DATA_PATH           = '/etc/flexiwan/agent/'
        self.FWAGENT_CONF_FILE   = self.DATA_PATH + 'fwagent_conf.yaml'  # Optional, if not present, defaults are taken
        self.DEVICE_TOKEN_FILE   = self.DATA_PATH + 'fwagent_info.txt'
        self.VERSIONS_FILE       = self.DATA_PATH + '.versions.yaml'
        self.SQLITE_DB_FILE      = self.DATA_PATH + '.requests.sqlite'
        self.ROUTER_STATE_FILE   = self.DATA_PATH + '.router.state'
        self.CONN_FAILURE_FILE   = self.DATA_PATH + '.upgrade_failed'
        self.ROUTER_LOG_FILE     = '/var/log/flexiwan/agent.log'
        self.SYSLOG_FILE         = '/var/log/syslog'
        self.DHCP_LOG_FILE     = '/var/log/dhcpd.log'
        self.VPP_LOG_FILE     = '/var/log/vpp/vpp.log'
        self.OSPF_LOG_FILE     = '/var/log/frr/ospfd.log'
        self.VPP_CONFIG_FILE     = '/etc/vpp/startup.conf'
        self.VPP_CONFIG_FILE_BACKUP = '/etc/vpp/startup.conf.orig'
        self.FRR_CONFIG_FILE     = '/etc/frr/daemons'
        self.FRR_OSPFD_FILE      = '/etc/frr/ospfd.conf'
        self.DHCPD_CONFIG_FILE = '/etc/dhcp/dhcpd.conf'
        self.APP_REC_DB_FILE = self.DATA_PATH + '.app_rec.sqlite'
        self.MULTILINK_DB_FILE = self.DATA_PATH + '.multilink.sqlite'
        self.DHCPD_CONFIG_FILE_BACKUP = '/etc/dhcp/dhcpd.conf.orig'
        self.FWAGENT_DAEMON_NAME = 'fwagent.daemon'
        self.FWAGENT_DAEMON_HOST = '127.0.0.1'
        self.FWAGENT_DAEMON_PORT = 9090
        self.FWAGENT_DAEMON_URI  = 'PYRO:%s@%s:%d' % (self.FWAGENT_DAEMON_NAME, self.FWAGENT_DAEMON_HOST, self.FWAGENT_DAEMON_PORT)
        self.WS_STATUS_CODE_NOT_APPROVED = 403
        self.WS_STATUS_DEVICE_CHANGE     = 900
        self.WS_STATUS_LOCAL_ERROR       = 999

        # Load configuration from file
        self.cfg = self.FwConfiguration(self.FWAGENT_CONF_FILE, self.DATA_PATH)

        # Load websocket status codes on which agent should reconnect into a list
        self.ws_reconnect_status_codes = []
        for a in dir(self):
            if re.match("WS_STATUS_", a):
                self.ws_reconnect_status_codes.append(getattr(self, a))


    def load_configuration_from_file(self):
        """Load configuration from YAML file.

        :returns: None.
        """
        # Load configuration
        self.cfg.__init__(self.FWAGENT_CONF_FILE, self.DATA_PATH)
        # Print loaded configuration into log
        if self.cfg.DEBUG:
            global log
            log.debug("Fwglobals configuration: " + self.__str__(), to_terminal=False)
            # for a in dir(self.cfg):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)
            # for a in dir(self):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)

    def initialize(self):
        """Initialize agent, router and OS API.
        Restore VPP if needed.

        :returns: None.
        """
        self.agent_api  = FWAGENT_API()
        self.router_api = FWROUTER_API(self.SQLITE_DB_FILE, self.MULTILINK_DB_FILE)
        self.os_api     = OS_API()
        self.apps_api   = FwApps(self.APP_REC_DB_FILE)
        self.policy_api = FwPolicies()

        self.router_api.restore_vpp_if_needed()

    def finalize(self):
        """Destructor method
        """
        self.router_api.finalize()

    def __str__(self):
        """Get string representation of configuration.

        :returns: String in JSON format.
        """
        return json.dumps({
            'MANAGEMENT_URL':       self.cfg.MANAGEMENT_URL,
            'TOKEN_FILE':           self.cfg.TOKEN_FILE,
            'BYPASS_CERT':          self.cfg.BYPASS_CERT,
            'DEBUG':                self.cfg.DEBUG,
            'UUID':                 self.cfg.UUID,
            'FWAGENT_CONF_FILE':    self.FWAGENT_CONF_FILE,
            'NUM_RETRIES_ALLOWED':  self.NUM_RETRIES_ALLOWED,
            'RETRY_INTERVAL_MIN':   self.RETRY_INTERVAL_MIN,
            'RETRY_INTERVAL_MAX':   self.RETRY_INTERVAL_MAX,
            }, indent = 2)

    def _call_agent_api(self, req, params):
        return self.agent_api.call(req, params)

    def _call_apps_api(self, req, params):
        return self.apps_api.call(req, params)

    def _call_policy_api(self, req, params):
        return self.policy_api.call(req, params)

    def _call_router_api(self, req, params):
        if req == 'aggregated-router-api':
            return self.router_api.call_aggregated(params['requests'])
        else:
            return self.router_api.call(req, params)

    def _call_os_api(self, req, params):
        return self.os_api.call_simple(req, params)

    def _call_vpp_api(self, req, params, result=None):
        return self.router_api.vpp_api.call_simple(req, params, result)

    def _call_python_api(self, req, params):
        func = self._call_python_api_get_func(req, params)
        args = params.get('args')
        if args:
            ret = func(args)
        else:
            ret = func()
        (ok, val) = self._call_python_api_parse_result(ret)
        if not ok:
            log.error('_call_python_api: %s(%s) failed: %s' % \
                    (params['func'], json.dumps(args), val))
        reply = {'ok':ok, 'message':val}
        return reply

    def _call_python_kwargs_api(self, req, params):
        func = self._call_python_api_get_func(req, params)
        ret = func(**params['args'])
        (ok, val) = self._call_python_api_parse_result(ret)
        if not ok:
            log.error('_call_python_kwargs_api: %s(%s) failed: %s' % \
                    (params['func'], json.dumps(params['args']), val))
        reply = {'ok':ok, 'message':val}
        return reply

    def _call_python_api_get_func(self, req, params):
        if 'module' in params:
            func = getattr(__import__(params['module']), params['func'])
        elif 'object' in params:
            if params['object'] == 'fwglobals.g':
                func = getattr(self, params['func'])
            elif params['object'] == 'fwglobals.g.router_api':
                func = getattr(self.router_api, params['func'])
            else:
                raise Exception("object '%s' is not supported" % (params['object']))
        else:
            raise Exception("neither 'module' nor 'object' was provided for '%s'" % (params['func']))
        return func

    def _call_python_api_parse_result(self, ret):
        val = None
        if ret is None:
            ok  = 1
        elif type(ret) == tuple:
            ok  = ret[0]
            val = ret[1]
        elif type(ret) == dict:
            ok  = ret.get('ok', 0)
            val = ret.get('ret')
        elif type(ret) == bool:
            ok = 1 if ret else 0
        else:
            ok = 0
            val = '_call_python_api_parse_result: unsupported type of return: %s' % type(ret)
        return (ok, val)


    # result - how to store result of command.
    #          It is dict of {<attr> , <cache>, <cache key>}.
    #          On success we fetch value of attribute <attr> of the object,
    #          returned by 'cmd' command and store it in the <cache> by key <cache key>.
    #          Note <attr> may be used for any semantic, depeneding on the command.
    #          For example, it might contain pattern for grep to be run
    #          on command output.
    #
    def handle_request(self, req, params=None, result=None, received_msg=None):
        """Handle request.

        :param req:          Request from flexiManage, e.g. 'start-router'
        :param params:       Parameters from flexiManage.
        :param result:       Place for result.
        :param received_msg: The original message received from flexiManage.

        :returns: Dictionary with error string and status code.
        """

        try:
            handler_name = request_handlers.get(req)
            assert handler_name, 'fwglobals: "%s" request is not supported' % req

            handler_func = getattr(self, handler_name)
            assert handler_func, 'fwglobals: handler=%s not found for req=%s' % (handler_name, req)

            if result is None:
                reply = handler_func(req, params)
            else:
                reply = handler_func(req, params, result)
            if reply['ok'] == 0:
                if 'usage' in params and params['usage'] != 'precondition':  # Don't generate error if precondition fails
                    myCmd = 'sudo vppctl api trace save error.api'
                    os.system(myCmd)
                    raise Exception(reply['message'])

            # On router configuration request, e.g. add-interface,
            # remove-tunnel, modify-device, etc. update the configuration database
            # signature. This is needed to assists the database synchronization
            # feature that keeps the configuration set by user on the flexiManage
            # in sync with the one stored on the flexiEdge device.
            # Note we do that here, as at this point we handle configuration
            # request that was received from flexiManage and that was not
            # generated locally.
            #
            if reply['ok'] == 1 and handler_name == '_call_router_api':
                # Update the configuration signature
                self.router_api.db_requests.update_signature(received_msg)
                # Add the updated signatire to the reply, so server could be quite
                reply['router-cfg-hash'] = self.router_api.db_requests.get_signature()

            return reply

        except Exception as e:
            global log
            err_str = "%s(%s): %s" % (req, format(params), str(e))
            log.error(err_str + ': %s' % traceback.format_exc())
            reply = {"message":err_str, 'ok':0}
            return reply


def initialize(log_level=Fwlog.FWLOG_LEVEL_INFO):
    """Initialize global instances of LOG, and GLOBALS.

    :param log_level:    LOG severity level.

    :returns: None.
    """
    global g_initialized
    if not g_initialized:
        global log
        log = Fwlog(log_level)
        global g
        g = Fwglobals()
        g_initialized = True
