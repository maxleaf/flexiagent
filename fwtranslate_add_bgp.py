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

import fwglobals
# {
#   "entity": "agent",
#   "message": "add-bgp",
#   "params": {
#       "routerId": "",
#       "holdInterval": "40",
#       "keepaliveInterval": "40",
#       "localASN": "35",
#       "neighbors": [
#       {
#           "ip": "8.8.8.8/31",
#           "remoteASN": "55",
#           "password": "abc"
#       },
#       {
#           "ip": "6.6.6.6/32",
#           "remoteASN": "44",
#           "password": "abc"
#       }
#   ]
# }
def add_bgp(params):
    """Change /etc/dhcp/dhcpd.conf config file.

    :param cmd_list:            List of commands.

    :returns: None.
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'if [ -n "$(grep bgpd=no %s)" ]; then sudo sed -i -E "s/bgpd=no/bgpd=yes/" %s; fi' % (fwglobals.g.FRR_DAEMONS_FILE, fwglobals.g.FRR_DAEMONS_FILE)]
    cmd['cmd']['descr']   = "start BGP daemon"
    cmd['revert'] = {}
    cmd['revert']['name']   = "exec"
    cmd['revert']['params'] = [ 'if [ -n "$(grep bgpd=yes %s)" ]; then sudo sed -i -E "s/bgpd=yes/bgpd=no/" %s; sudo systemctl restart frr; fi' % (fwglobals.g.FRR_DAEMONS_FILE, fwglobals.g.FRR_DAEMONS_FILE)]
    cmd['revert']['descr']  = "stop BGP daemon"
    cmd_list.append(cmd)

    localASN = params.get('localASN')
    router_bgp_asn = 'router bgp %s' % localASN
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']   = "python"
    cmd['cmd']['descr']   =  "set bgp router with %s ASN" % localASN
    cmd['cmd']['params'] = {
            'module': 'fwutils',
            'func': 'frr_vtysh_run',
            'args': {
                'flags'              : '-c "configure" -c "%s"' % router_bgp_asn,
                'restart_frr_service': True,
            }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['params'] = {
            'module': 'fwutils',
            'func': 'frr_vtysh_run',
            'args': {
                'flags': '-c "configure" -c "no %s"' % router_bgp_asn
            }
    }
    cmd['revert']['descr']   =  "remove bgp router with %s ASN" % localASN
    cmd_list.append(cmd)


    vty_commands = []
    restart_frr = False

    routerId = params.get('routerId')
    if routerId:
        vty_commands.append('bgp router-id %s' % routerId)
        restart_frr = True

    neighbors = params.get('neighbors')
    keepaliveInterval = params.get('keepaliveInterval')
    holdInterval = params.get('holdInterval')
    if neighbors:
        for neighbor in neighbors:
            ip = neighbor['ip']
            remoteASN = neighbor['remoteASN']
            vty_commands.append('neighbor %s remote-as %s' % (ip, remoteASN))

            password = neighbor.get('password')
            if password:
                vty_commands.append('neighbor %s password %s' % (ip, password))

            if keepaliveInterval and holdInterval:
                vty_commands.append('neighbor %s timers %s %s' % (ip, keepaliveInterval, holdInterval))

    if vty_commands:
        frr_cmd = ' -c '.join(map(lambda x: '"%s"' % x, vty_commands))
        # reverse the frr_cmd_revert because we need to start removing from the last config
        #
        frr_cmd_revert = ' -c '.join(map(lambda x: '"no %s"' % x, list(reversed(vty_commands))))

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']   = "python"
        cmd['cmd']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'flags'              : '-c "configure" -c "%s" -c %s' % (router_bgp_asn, frr_cmd),
                    'restart_frr_service': restart_frr
                }
        }
        cmd['cmd']['descr']   =  "add BGP configurations"
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['params'] = {
                'module': 'fwutils',
                'func': 'frr_vtysh_run',
                'args': {
                    'flags'              : '-c "configure" -c "%s" -c %s' % (router_bgp_asn, frr_cmd_revert),
                    'restart_frr_service': restart_frr
                }
        }
        cmd['revert']['descr']   =  "remove BGP configurations"
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-dhcp-config command.

    :param params:        Parameters from flexiManage.

    :returns: add-dhcp-config command.
    """
    key = 'add-bgp-config'
    return key
