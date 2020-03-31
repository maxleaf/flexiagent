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

fwpolicy_api = {
    'add-policy-info':         '_add_policy_info',
    'remove-policy-info':      '_remove_policy_info',
}

class FwPolicies:
    """Policies class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        self.policies_map = {}

    def call(self, req, params):
        """Invokes API specified by the 'req' parameter.

        :param req: Request name.
        :param params: Parameters from flexiManage.

        :returns: Reply.
        """
        handler = fwpolicy_api.get(req)
        assert handler, 'fwpolicy_api: "%s" request is not supported' % req

        handler_func = getattr(self, handler)
        assert handler_func, 'fwpolicy_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            raise Exception("fwpolicy_api: %s(%s) failed: %s" % (handler_func, format(params), reply['message']))
        return reply

    def _add_policy_info(self, params):
        """Save policy information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        self.policies_map[params['id']] = params

        reply = {'ok': 1}
        return reply

    def _remove_policy_info(self, params):
        """Remove policy information.

        :param params: Parameters from flexiManage.

        :returns: Dictionary with information and status code.
        """
        del self.policies_map[params['id']]

        reply = {'ok': 1}
        return reply
