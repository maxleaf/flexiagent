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

import copy
import json
import os
import Pyro4
import re
import signal
import time
import traceback
import yaml
import fwutils
import threading

from sqlitedict import SqliteDict

from fwagent import FwAgent
from fwrouter_api import FWROUTER_API
from fwsystem_api import FWSYSTEM_API
from fwagent_api import FWAGENT_API
from os_api import OS_API
from fwlog import Fwlog
from fwapplications import FwApps
from fwpolicies import FwPolicies
from fwrouter_cfg import FwRouterCfg
from fwsystem_cfg import FwSystemCfg
from fwstun_wrapper import FwStunWrap
from fwwan_monitor import FwWanMonitor

# sync flag indicated if module implement sync logic. 
# IMPORTANT! Please keep the list order. It indicates the sync priorities
modules = {
    'fwsystem_api':     { 'module': __import__('fwsystem_api'),   'sync': True,  'object': 'system_api' }, # fwglobals.g.system_api
    'fwagent_api':      { 'module': __import__('fwagent_api'),    'sync': False, 'object': 'agent_api' },  # fwglobals.g.agent_api
    'fwapplications':   { 'module': __import__('fwapplications'), 'sync': False, 'object': 'apps' }, # fwglobals.g.apps
    'fwrouter_api':     { 'module': __import__('fwrouter_api'),   'sync': True,  'object': 'router_api' }, # fwglobals.g.router_api
    'os_api':           { 'module': __import__('os_api'),         'sync': False, 'object': 'os_api' }, # fwglobals.g.os_api
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
    'get-device-info':                   {'name': '_call_agent_api'},
    'get-device-stats':                  {'name': '_call_agent_api'},
    'get-device-logs':                   {'name': '_call_agent_api'},
    'get-device-packet-traces':          {'name': '_call_agent_api'},
    'get-device-os-routes':              {'name': '_call_agent_api'},
    'get-device-config':                 {'name': '_call_agent_api'},
    'upgrade-device-sw':                 {'name': '_call_agent_api'},
    'reset-device':                      {'name': '_call_agent_api'},
    'sync-device':                       {'name': '_call_agent_api'},
    'get-wifi-info':                     {'name': '_call_agent_api'},
    'get-lte-info':                      {'name': '_call_agent_api'},
    'reset-lte':                         {'name': '_call_agent_api'},

    # Router API
    'aggregated':                   {'name': '_call_router_api', 'sign': True},
    'start-router':                 {'name': '_call_router_api', 'sign': True},
    'stop-router':                  {'name': '_call_router_api', 'sign': True},
    'add-interface':                {'name': '_call_router_api', 'sign': True},
    'remove-interface':             {'name': '_call_router_api', 'sign': True},
    'modify-interface':             {'name': '_call_router_api', 'sign': True},
    'add-route':                    {'name': '_call_router_api', 'sign': True},
    'remove-route':                 {'name': '_call_router_api', 'sign': True},
    'add-tunnel':                   {'name': '_call_router_api', 'sign': True},
    'remove-tunnel':                {'name': '_call_router_api', 'sign': True},
    'add-dhcp-config':              {'name': '_call_router_api', 'sign': True},
    'remove-dhcp-config':           {'name': '_call_router_api', 'sign': True},
    'add-application':              {'name': '_call_router_api', 'sign': True},
    'remove-application':           {'name': '_call_router_api', 'sign': True},
    'add-multilink-policy':         {'name': '_call_router_api', 'sign': True},
    'remove-multilink-policy':      {'name': '_call_router_api', 'sign': True},

    # System API
    'add-lte':                        {'name': '_call_system_api'},
    'remove-lte':                     {'name': '_call_system_api'},

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
    'cpuutil':                      {'name': '_call_os_api'},
    'exec':                         {'name': '_call_os_api'},
    'ifcount':                      {'name': '_call_os_api'},
    'ifstats':                      {'name': '_call_os_api'},

    # VPP API
    'abf_itf_attach_add_del':       {'name': '_call_vpp_api'},
    'abf_policy_add_del':           {'name': '_call_vpp_api'},
    'acl_add_replace':              {'name': '_call_vpp_api'},
    'acl_del':                      {'name': '_call_vpp_api'},
    'bridge_domain_add_del':        {'name': '_call_vpp_api'},
    'create_loopback_instance':     {'name': '_call_vpp_api'},
    'delete_loopback':              {'name': '_call_vpp_api'},
    'ipsec_gre_add_del_tunnel':     {'name': '_call_vpp_api'},
    'ipsec_sad_add_del_entry':      {'name': '_call_vpp_api'},
    'ipsec_spd_add_del':            {'name': '_call_vpp_api'},
    'ipsec_interface_add_del_spd':  {'name': '_call_vpp_api'},
    'ipsec_spd_add_del_entry':      {'name': '_call_vpp_api'},
    'l2_flags':                     {'name': '_call_vpp_api'},
    'nat44_add_del_interface_addr':             {'name': '_call_vpp_api'},
    'nat44_interface_add_del_output_feature':   {'name': '_call_vpp_api'},
    'nat44_forwarding_enable_disable':          {'name': '_call_vpp_api'},
    'nat44_add_del_identity_mapping':           {'name': '_call_vpp_api'},
    'sw_interface_add_del_address': {'name': '_call_vpp_api'},
    'sw_interface_set_flags':       {'name': '_call_vpp_api'},
    'sw_interface_set_l2_bridge':   {'name': '_call_vpp_api'},
    'sw_interface_set_mac_address': {'name': '_call_vpp_api'},
    'sw_interface_set_mtu':         {'name': '_call_vpp_api'},
    'vmxnet3_create':               {'name': '_call_vpp_api'},
    'vmxnet3_delete':               {'name': '_call_vpp_api'},
    'vxlan_add_del_tunnel':         {'name': '_call_vpp_api'},

    # Python API
    'python':                       {'name': '_call_python_api'}
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
            DEFAULT_MONITOR_UNASSIGNED_INTERFACES = True
            try:
                with open(filename, 'r') as conf_file:
                    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
                agent_conf = conf.get('agent', {})
                self.BYPASS_CERT    = agent_conf.get('bypass_certificate', DEFAULT_BYPASS_CERT)
                self.DEBUG          = agent_conf.get('debug',  DEFAULT_DEBUG)
                self.MANAGEMENT_URL = agent_conf.get('server', DEFAULT_MANAGEMENT_URL)
                self.TOKEN_FILE     = agent_conf.get('token',  DEFAULT_TOKEN_FILE)
                self.UUID           = agent_conf.get('uuid',   DEFAULT_UUID)
                self.MONITOR_UNASSIGNED_INTERFACES = agent_conf.get('monitor_unassigned_interfaces', DEFAULT_MONITOR_UNASSIGNED_INTERFACES)
            except Exception as e:
                log.excep("%s, set defaults" % str(e))
                self.BYPASS_CERT    = DEFAULT_BYPASS_CERT
                self.DEBUG          = DEFAULT_DEBUG
                self.MANAGEMENT_URL = DEFAULT_MANAGEMENT_URL
                self.TOKEN_FILE     = DEFAULT_TOKEN_FILE
                self.UUID           = DEFAULT_UUID
                self.MONITOR_UNASSIGNED_INTERFACES = DEFAULT_MONITOR_UNASSIGNED_INTERFACES
            if self.DEBUG:
                log.set_level(Fwlog.FWLOG_LEVEL_DEBUG)

    class FwCache:
        """Storage for data that is valid during one FwAgent lifecycle only.
        """
        def __init__(self):
            self.db = {
                'LINUX_INTERFACES': {},
                'DEV_ID_TO_VPP_IF_NAME': {},
                'DEV_ID_TO_VPP_TAP_NAME': {},
                'STUN': {},
                'VPP_IF_NAME_TO_DEV_ID': {},
                'LINUX_IF_NAME_TO_DEV_ID': {},
                'WAN_MONITOR': {
                    'enabled_routes':  {},
                    'disabled_routes': {},
                }
            }
            self.lock                = threading.Lock()
            self.linux_interfaces    = self.db['LINUX_INTERFACES']
            self.dev_id_to_vpp_if_name  = self.db['DEV_ID_TO_VPP_IF_NAME']
            self.dev_id_to_vpp_tap_name = self.db['DEV_ID_TO_VPP_TAP_NAME']
            self.stun_cache          = self.db['STUN']
            self.vpp_if_name_to_dev_id  = self.db['VPP_IF_NAME_TO_DEV_ID']
            self.linux_if_to_dev_id  = self.db['LINUX_IF_NAME_TO_DEV_ID']
            self.wan_monitor         = self.db['WAN_MONITOR']


    def __init__(self):
        """Constructor method
        """
        # Set default configuration
        self.RETRY_INTERVAL_MIN  = 5 # seconds - is used for both registration and main connection
        self.RETRY_INTERVAL_MAX  = 15
        self.RETRY_INTERVAL_LONG_MIN = 50
        self.RETRY_INTERVAL_LONG_MAX = 70
        self.DATA_PATH           = '/etc/flexiwan/agent/'
        self.FWAGENT_CONF_FILE   = self.DATA_PATH + 'fwagent_conf.yaml'  # Optional, if not present, defaults are taken
        self.DEVICE_TOKEN_FILE   = self.DATA_PATH + 'fwagent_info.txt'
        self.VERSIONS_FILE       = self.DATA_PATH + '.versions.yaml'
        self.ROUTER_CFG_FILE     = self.DATA_PATH + '.requests.sqlite'
        self.SYSTEM_CFG_FILE     = self.DATA_PATH + '.system.sqlite'
        self.ROUTER_STATE_FILE   = self.DATA_PATH + '.router.state'
        self.CONN_FAILURE_FILE   = self.DATA_PATH + '.upgrade_failed'
        self.ROUTER_LOG_FILE     = '/var/log/flexiwan/agent.log'
        self.SYSLOG_FILE         = '/var/log/syslog'
        self.DHCP_LOG_FILE       = '/var/log/dhcpd.log'
        self.VPP_LOG_FILE        = '/var/log/vpp/vpp.log'
        self.OSPF_LOG_FILE       = '/var/log/frr/ospfd.log'
        self.VPP_CONFIG_FILE     = '/etc/vpp/startup.conf'
        self.VPP_CONFIG_FILE_BACKUP   = '/etc/vpp/startup.conf.baseline'
        self.VPP_CONFIG_FILE_RESTORE = '/etc/vpp/startup.conf.orig'
        self.FRR_CONFIG_FILE     = '/etc/frr/daemons'
        self.FRR_OSPFD_FILE      = '/etc/frr/ospfd.conf'
        self.DHCPD_CONFIG_FILE   = '/etc/dhcp/dhcpd.conf'
        self.APP_REC_DB_FILE     = self.DATA_PATH + '.app_rec.sqlite'
        self.POLICY_REC_DB_FILE  = self.DATA_PATH + '.policy.sqlite'
        self.MULTILINK_DB_FILE   = self.DATA_PATH + '.multilink.sqlite'
        self.DATA_DB_FILE        = self.DATA_PATH + '.data.sqlite'
        self.DHCPD_CONFIG_FILE_BACKUP = '/etc/dhcp/dhcpd.conf.orig'
        self.HOSTAPD_CONFIG_DIRECTORY = '/etc/hostapd/'
        self.NETPLAN_FILES       = {}
        self.NETPLAN_FILE        = '/etc/netplan/99-flexiwan.fwrun.yaml'
        self.FWAGENT_DAEMON_NAME = 'fwagent.daemon'
        self.FWAGENT_DAEMON_HOST = '127.0.0.1'
        self.FWAGENT_DAEMON_PORT = 9090
        self.FWAGENT_DAEMON_URI  = 'PYRO:%s@%s:%d' % (self.FWAGENT_DAEMON_NAME, self.FWAGENT_DAEMON_HOST, self.FWAGENT_DAEMON_PORT)
        self.WS_STATUS_ERROR_NOT_APPROVED = 403
        self.WS_STATUS_ERROR_LOCAL_ERROR  = 800 # Should be over maximal HTTP STATUS CODE - 699
        self.fwagent = None
        self.cache   = self.FwCache()
        self.WAN_FAILOVER_SERVERS          = [ '1.1.1.1' , '8.8.8.8' ]
        self.WAN_FAILOVER_WND_SIZE         = 20         # 20 pings, every ping waits a second for response
        self.WAN_FAILOVER_THRESHOLD        = 12         # 60% of pings lost - enter the bad state, 60% of pings are OK - restore to good state
        self.WAN_FAILOVER_METRIC_WATERMARK = 2000000000 # Bad routes will have metric above 2000000000
        self.DUMP_FOLDER                   = '/var/log/flexiwan/fwdump'


        # Load configuration from file
        self.cfg = self.FwConfiguration(self.FWAGENT_CONF_FILE, self.DATA_PATH)

        self.db = SqliteDict(self.DATA_DB_FILE, autocommit=True)  # IMPORTANT! set the db variable regardless of agent initialization

        # Load websocket status codes on which agent should reconnect into a list
        self.ws_reconnect_status_codes = []
        for a in dir(self):
            if re.match("WS_STATUS_", a):
                self.ws_reconnect_status_codes.append(getattr(self, a))

        # Load signal to string map
        self.signal_names = dict((getattr(signal, n), n) \
                                for n in dir(signal) if n.startswith('SIG') and '_' not in n )


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

    def initialize_agent(self, standalone=False):
        """Initialize singleton object. Restore VPP if needed.

        :param standalone: if True, the agent will be not connected to flexiManage,
                           hence no need in network activity, like STUN.
                           The standalone mode is used by CLI-based tests.
        """
        if self.fwagent:
            global log
            log.warning('Fwglobals.initialize_agent: agent exists')
            return self.fwagent

        self.db           = SqliteDict(self.DATA_DB_FILE, autocommit=True)  # IMPORTANT! Load data at the first place!
        self.fwagent      = FwAgent(handle_signals=False)
        self.router_cfg   = FwRouterCfg(self.ROUTER_CFG_FILE) # IMPORTANT! Initialize database at the first place!
        self.system_cfg   = FwSystemCfg(self.SYSTEM_CFG_FILE)
        self.agent_api    = FWAGENT_API()
        self.system_api   = FWSYSTEM_API(self.system_cfg)
        self.router_api   = FWROUTER_API(self.router_cfg, self.MULTILINK_DB_FILE)
        self.os_api       = OS_API()
        self.apps         = FwApps(self.APP_REC_DB_FILE)
        self.policies     = FwPolicies(self.POLICY_REC_DB_FILE)
        self.stun_wrapper = FwStunWrap(standalone)
        self.stun_wrapper.initialize()

        self.system_api.restore_configuration() # IMPORTANT! The System configurations should be restored before restore_vpp_if_needed!
        self.router_api.restore_vpp_if_needed()

        fwutils.get_linux_interfaces(cached=False) # Fill global interface cache

        self.wan_monitor = FwWanMonitor(standalone) # IMPORTANT! The WAN monitor should be initialized after restore_vpp_if_needed!

        return self.fwagent

    def finalize_agent(self):
        """Destructor method
        """
        if not self.fwagent:
            global log
            log.warning('Fwglobals.finalize_agent: agent does not exists')
            return

        self.wan_monitor.finalize()
        self.stun_wrapper.finalize()
        self.router_api.finalize()
        self.fwagent.finalize()
        self.router_cfg.finalize() # IMPORTANT! Finalize database at the last place!

        del self.wan_monitor
        del self.stun_wrapper
        del self.apps
        del self.policies
        del self.os_api
        del self.router_api
        del self.agent_api
        del self.fwagent
        self.fwagent = None
        self.db.close()
        return

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
            'RETRY_INTERVAL_MIN':   self.RETRY_INTERVAL_MIN,
            'RETRY_INTERVAL_MAX':   self.RETRY_INTERVAL_MAX,
            }, indent = 2)

    def _call_agent_api(self, request):
        return self.agent_api.call(request)

    def _call_system_api(self, request):
        return self.system_api.call(request)

    def _call_router_api(self, request):
        return self.router_api.call(request)

    def _call_os_api(self, request):
        return self.os_api.call_simple(request)

    def _call_vpp_api(self, request, result=None):
        return self.router_api.vpp_api.call_simple(request, result)

    def _call_python_api(self, request, result=None):
        '''Handle request that describe python function.

        :param request: the request like:
            {
                'name':   "python"
                'descr':  "add multilink labels into interface %s %s: %s" % (iface_addr, iface_dev_id, labels)
                'params': {
                    'module': 'fwutils',
                    'func'  : 'vpp_multilink_update_labels',
                    'args'  : {
                        'labels':   labels,
                        'next_hop': gw,
                        'dev_id':   iface_dev_id,
                        'remove':   False
                    }
                }
            }

        :param result: the cache where the python function should store data,
                       required by the request sender. Today this cache is
                       managed by the router_api executor and it is used
                       to fulfill substitutions in function arguments,
                       specified by the 'substs' parameter of the request.
                       The format of the 'result' is as follows:
            {
                'result_attr': <name of variable inside python function,
                                value of which the function should set into cache>
                'cache':       <the python dict used as a cache>
                'key':         <the key for the value to be cached>
            }
        '''
        func = self._call_python_api_get_func(request['params'])
        args = request['params'].get('args')

        if result:
            args = copy.deepcopy(args) if args else {}
            args.update({ 'result_cache': result })

        ret = func(**args) if args else func()
        (ok, val) = self._call_python_api_parse_result(ret)
        if not ok:
            func_str = request['params'].get('func')
            if args:
                args_str = ', '.join([ "%s=%s" % (arg_name, args[arg_name]) for arg_name in args ])
            else:
                args_str = ''
            log.error('_call_python_api: %s(%s) failed: %s' % (func_str, args_str, val))
        reply = {'ok':ok, 'message':val}
        return reply

    def _call_python_api_get_func(self, params):
        if 'module' in params:
            func = getattr(__import__(params['module']), params['func'])
        elif 'object' in params:
            if params['object'] == 'fwglobals.g':
                func = getattr(self, params['func'])
            elif params['object'] == 'fwglobals.g.router_api':
                func = getattr(self.router_api, params['func'])
            elif params['object'] == 'fwglobals.g.router_api.vpp_api':
                func = getattr(self.router_api.vpp_api, params['func'])
            elif params['object'] == 'fwglobals.g.apps':
                func = getattr(self.apps, params['func'])
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
    def handle_request(self, request, result=None, received_msg=None):
        """Handle request.

        :param request:      The request received from flexiManage after
                             transformation by fwutils.fix_received_message().
        :param result:       Place for result.
        :param received_msg: The original message received from flexiManage.

        :returns: Dictionary with error string and status code.
        """
        try:
            req    = request['message']
            params = request.get('params')

            if req != 'aggregated':
                handler = request_handlers.get(req)
                assert handler, 'fwglobals: "%s" request is not supported' % req
            else:
                # In case of aggregated request use the first request in aggregation
                # to deduce the handler function.
                # Note the aggregation might include requests of the same type
                # only, e.g. Router API (add-tunnel, remove-application, etc)
                #
                handler = request_handlers.get(params['requests'][0]['message'])
                assert handler, 'fwglobals: aggregation with "%s" request is not supported' % \
                    params['requests'][0]['message']

            # Keep copy of the request aside for signature purposes,
            # as the original request might by modified by preprocessing.
            #
            if handler.get('sign', False) == True and received_msg is None:
                received_msg = copy.deepcopy(request)

            handler_func = getattr(self, handler.get('name'))

            if result is None:
                reply = handler_func(request)
            else:
                reply = handler_func(request, result)
            if reply['ok'] == 0:
                myCmd = 'sudo vppctl api trace save error.api'
                os.system(myCmd)
                raise Exception(reply['message'])

            # On router configuration request, e.g. add-interface,
            # remove-tunnel, etc. update the configuration database
            # signature. This is needed to assists the database synchronization
            # feature that keeps the configuration set by user on the flexiManage
            # in sync with the one stored on the flexiEdge device.
            # Note we update signature on configuration requests only, but
            # retrieve it into replies for all requests. This is to simplify
            # flexiManage code.
            #
            if reply['ok'] == 1 and handler.get('sign', False) == True:
                fwutils.update_device_config_signature(received_msg)
            reply['router-cfg-hash'] = fwutils.get_device_config_signature()

            return reply

        except Exception as e:
            global log
            err_str = "%s(%s): %s" % (str(e), req, format(params))
            log.error(err_str + ': %s' % str(traceback.format_exc()))
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
