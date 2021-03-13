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

import types
import fwglobals

class _VPP_DECODER:
    """This is Dummy VPP DECODER class representation.
    """
    def __init__(selfd, inp):
        selfd.inp = inp
    def decode(selfd):
        return selfd.inp
    def __str__(selfd):
        return selfd.inp
    
class _VPP_DECODER_API:
    """This is Dummy VPP DECODER API class representation.
    """
    def __init__(selfda, inp):
        selfda.d = inp
    def __getattr__(selfda, name):
        return _VPP_DECODER(selfda.d + ",decode:"+name)

class _VPP_API:
    """This is Dummy VPP API class representation.
    """
    def __init__(selfapi):
        fwglobals.log.debug("..VAPI init")
    # If name begins with f create a method
    def __getattr__(selfapi, name):
        def myfunc(selfapi, *argv, **kwargs):
            return _VPP_DECODER_API("api:"+ name + ",args:" + str(argv) + str(kwargs))
        # Python 2 get 3 parameters while 3 two
        try:
            meth = types.MethodType(myfunc, selfapi, _VPP_API)
        except TypeError:
            meth = types.MethodType(myfunc, selfapi)
        return meth

class VPPApiClient:
    """This is Dummy VPP class representation.
    """
    def __init__(self, apifiles, use_socket=False, read_timeout=5):
        """Constructor method
        """
        self.api = _VPP_API()
        fwglobals.log.debug("VPP Init: " + str(apifiles))
    def connect(self, name="default-conn"):
        """Connect to dummy VPP.
        """
        fwglobals.log.debug("Connect: " + name)
    def disconnect(self):
        """Disconnect from dummy VPP.
        """
        fwglobals.log.debug("Disconnect")
