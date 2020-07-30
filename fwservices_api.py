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

fwservices_api = {
    'install-service':       '_install_service',
    'uninstall-service':     '_uninstall_service',
    'modify-service':        '_modify_service',
    'upgrade-service':       '_upgrade_service',    
}

services = {
    'open-vpn':          {
        'install': fwutils.install_openvpn_server,
        'uninstall': fwutils.remove_openvpn_server,
        'modify': fwutils.configure_openvpn_server,
        'upgrade': fwutils.install_openvpn_server
    },
}

class FwServices:
    """Services class representation.
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

        service = services.get(params['type'])
        assert service, '%s: "%s" app is not supported' % (req, params['type'])

        handler = fwservices_api.get(req)
        assert handler, 'fwservices_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwservices_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwservices_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _install_service(self, params):
        """Install service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            services[params['type']]['install'](params['config'])
            reply = {'ok': 1}
        except:
            services[params['type']]['uninstall']()
            reply = {'ok': 0}

        return reply

    def _uninstall_service(self, params):
        """Uninstall service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        services[params['type']]['uninstall']()
        reply = {'ok': 1}

        return reply
    
    def _modify_service(self, params):
        """Modify service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        services[params['type']]['modify'](params['config'])

        reply = {'ok': 1}
        return reply

    def _upgrade_service(self, params):
        """Upgrade service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        services[params['type']]['upgrade'](params['config'])

        reply = {'ok': 1}
        return reply