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
        message = req['message']
        params = req['params']
        service_type = params['type']
        
        service = services.get(service_type)
        assert service, '%s: "%s" service is not supported' % (message, service_type)
        
        reply = {'ok': 1}
        if (message == 'install-service'):
            try:
                service.install(params['config'])
            except:
                service.uninstall()
                reply = {'ok': 0}
        elif message == 'uninstall-service':
            try:
                service.uninstall()
            except:
                reply = {'ok': 0}
        elif message == 'modify-service':
            try:
                service.modify(params['config'])
            except:
                reply = {'ok': 0}
        elif message == 'upgrade-service':
            try:
                service.upgrade(params['config'])
            except:
                reply = {'ok': 0}
        else:
            reply = {'ok': 0}

        if reply['ok'] == 0:
            reply = {'entity':'servicesReply', 'message': False, 'ok': 0}
        else:
            reply = {'entity':'servicesReply', 'message': True, 'ok': 1}
        return reply