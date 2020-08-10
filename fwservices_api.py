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

import services.openvpn

fwservices_api = {
    'install-service':       '_install_service',
    'uninstall-service':     '_uninstall_service',
    'modify-service':        '_modify_service',
    'upgrade-service':       '_upgrade_service',    
}

services = {
    'open-vpn': services.openvpn
}

class FwServices:
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """

    def call(self, req):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        params = req['params']
        
        service = services.get(params['type'])
        assert service, '%s: "%s" app is not supported' % (req, params['type'])

        handler = fwservices_api.get(req['message'])
        assert handler, 'fwservices_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwservices_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(service, params)

        if reply['ok'] == 0:
            reply = {'entity':'servicesReply', 'message': "fwservices_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']), 'ok': 0}
        else:
            reply = {'entity':'servicesReply', 'message': True, 'ok': 1}
        return reply

    def _install_service(self, module, params):
        """Install service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            module.install(params['config'])
            reply = {'ok': 1}
        except:
            module.uninstall()
            reply = {'ok': 0}

        return reply

    def _uninstall_service(self, module, params):
        """Uninstall service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            module.uninstall()
            reply = {'ok': 1}
        except:
            reply = {'ok': 0}

        return reply
    
    def _modify_service(self, module, params):
        """Modify service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            module.modify(params['config'])
            reply = {'ok': 1}
        except:
            reply = {'ok': 0}

        return reply

    def _upgrade_service(self, module, params):
        """Upgrade service.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        try:
            module.upgrade(params['config'])
            reply = {'ok': 1}
        except:
            reply = {'ok': 0}

        return reply