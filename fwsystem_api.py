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

import time
import threading
import traceback
import subprocess
import fwglobals
import fwutils
import os
from fwcfg_request_handler import FwCfgRequestHandler

fwsystem_translators = {
    'add-lte':               {'module': __import__('fwtranslate_add_lte'),    'api':'add_lte'},
    'remove-lte':            {'module': __import__('fwtranslate_revert'),    'api':'revert'},
}

class FWSYSTEM_API(FwCfgRequestHandler):
    """This is System API class representation.
        These APIs are used to handle system configuration requests regardless of the vpp state.
        e.g to enable lte connection even if the vpp is not running.
        They are invoked by the flexiManage over secure WebSocket
        connection using JSON requests.
        For list of available APIs see the 'fwsystem_translators' variable.
    """
    def __init__(self, cfg):
        """Constructor method
        """
        FwCfgRequestHandler.__init__(self, fwsystem_translators, cfg, fwglobals.g.system_cfg)
        self.thread_lte_watchdog = None

    def initialize(self):
        if self.thread_lte_watchdog is None:
            self.thread_lte_watchdog = threading.Thread(target=self.lte_watchdog, name='LTE Watchdog')
            self.thread_lte_watchdog.start()

    def finalize(self):
        if self.thread_lte_watchdog:
            self.thread_lte_watchdog.join()
            self.thread_lte_watchdog = None

    def lte_watchdog(self):
        """LTE watchdog thread.
        Monitors proper configuration of LTE modem. The modem is configured
        and connected to provider by 'add-lte' request received from flexiManage
        with no relation to vpp. As long as it was not removed by 'remove-lte',
        it should stay connected and the IP address and other configuration
        parameters received from provider should match these configured in linux
        for the correspondent interface.
        """
        while not fwglobals.g.teardown:
            try: # Ensure thread doesn't exit on exception

                time.sleep(1)

                if  fwglobals.g.router_api.state_is_starting_stopping():
                    continue

                current_time = int(time.time())

                wan_list = fwglobals.g.system_cfg.dump(types=['add-lte'])
                for wan in wan_list:
                    dev_id = wan['params']['dev_id']
                    modem_mode = fwutils.get_lte_cache(dev_id, 'state')
                    if modem_mode == 'resetting' or modem_mode == 'connecting':
                        continue

                    is_assigned = fwutils.is_interface_assigned_to_vpp(dev_id)
                    if is_assigned and fwglobals.g.router_api.state_is_started():
                        name = fwutils.dev_id_to_tap(dev_id)
                    else:
                        name = fwutils.dev_id_to_linux_if(dev_id)

                    # Ensure that lte connection is opened.
                    # Sometimes, the connection between modem and provider becomes disconnected
                    #
                    if current_time % 10 == 0:
                        cmd = "fping 8.8.8.8 -C 1 -q -R -I %s > /dev/null 2>&1" % name
                        ok = not subprocess.call(cmd, shell=True)
                        if not ok:
                            connected = fwutils.mbim_is_connected(dev_id)
                            if not connected:
                                fwglobals.log.debug("lte modem is disconnected on %s" % dev_id)
                                fwglobals.g.system_api.restore_configuration(types=['add-lte'])
                                continue

                            # Make sure that LTE Linux interface is up
                            linux_ifc_name = fwutils.dev_id_to_linux_if(dev_id)
                            os.system('ifconfig %s up' % linux_ifc_name)
                            
                    # Ensure that provider did not change IP provisioned to modem,
                    # so the IP that we assigned to the modem interface is still valid.
                    # If it was changed, go and update the interface, vpp, etc.
                    #
                    if current_time % 60 == 0:
                        modem_addr = fwutils.lte_get_ip_configuration(dev_id, 'ip', False)
                        if modem_addr:
                            iface_addr = fwutils.get_interface_address(name, log=False)

                            if iface_addr != modem_addr:
                                fwglobals.log.debug("%s: LTE IP change detected: %s -> %s" % (dev_id, iface_addr, modem_addr))

                                fwutils.configure_lte_interface({
                                    'dev_id': dev_id,
                                    'metric': wan['params']['metric']
                                })

                                interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
                                if len(interfaces) > 0:
                                    params = interfaces[0]
                                    params['addr'] = modem_addr
                                    params['gateway'] = fwutils.lte_get_ip_configuration(dev_id, 'gateway')
                                    fwglobals.g.handle_request({'message':'modify-interface','params': params})

                                    fwglobals.log.debug("%s: LTE IP was changed: %s -> %s" % (dev_id, iface_addr, modem_addr))

            except Exception as e:
                fwglobals.log.error("%s: %s (%s)" %
                    (threading.current_thread().getName(), str(e), traceback.format_exc()))
                pass

