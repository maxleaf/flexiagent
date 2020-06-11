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

import fwutils
import fwglobals

fwvpn_api = {
    'install-vpn-server':      '_install_vpn_server',
    'remove-vpn-server':       '_remove_vpn_server',
    'configure-vpn-server':    '_configure_vpn_server',
    'upgrade-vpn-server':      '_upgrade_vpn_server'        
}

class FwVPN:
    """VPN class representation.
    """

    def __init__(self):
        """Constructor method.
        """

    def call(self, req, params):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        handler = fwvpn_api.get(req)
        assert handler, 'fwvpn_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwvpn_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwvpn_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _install_vpn_server(self, params):
        """Install VPN server.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        fwutils.install_openvpn_server(params)

        reply = {'ok': 1}
        return reply

    def _remove_vpn_server(self, params):
        """Remove VPN server.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        # fwutils.vpp_multilink_update_policy_rule(params)

        reply = {'ok': 1}
        return reply

    def _configure_vpn_server(self, params):
        """Configure VPN server.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """

        reply = {'ok': 1}
        return reply

    def _upgrade_vpn_server(self, params):
        """Upgrade VPN server.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """

        reply = {'ok': 1}
        return reply
    
