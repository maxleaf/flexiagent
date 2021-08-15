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

fwservices = {
    'open-vpn': services.openvpn.OpenVPN()
}

fwservices_handlers = {
    'install-service':   {'handler': 'install'},
    'uninstall-service': {'handler': 'uninstall'},
    'modify-service':    {'handler': 'modify'},
    'upgrade-service':   {'handler': 'upgrade'}
}

class FWSERVICES_API:
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """

    def call(self, request):
        """Invokes API specified by the 'request' parameter.

        :param request: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        message = request['message']
        params = request['params']
        service_type = params['type']

        service = fwservices.get(service_type)
        assert service, '%s: "%s" service is not supported' % (message, service_type)

        handler = fwservices_handlers.get(message)
        assert handler, '%s: "%s" handler is not supported' % (message, message)

        handler_func = getattr(service, handler['handler'])
        assert handler_func, '%s: "%s" function is not implemented fro this service' % (message, handler_func)

        try:
            (success, error) = handler_func(params['config'])

            if success == False:
                raise Exception(error)

            reply = {'entity':'servicesReply', 'message': 'success', 'ok': 1}
        except Exception as e:
            reply = {'entity':'servicesReply', 'message': str(e), 'ok': 0}

        return reply