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

import fwglobals
from fwrequest_executer import FwRequestExecuter

fwsystem_modules = {
    'fwtranslate_revert':       __import__('fwtranslate_revert') ,
    'fwtranslate_add_lte':      __import__('fwtranslate_add_lte'),
}

fwsystem_translators = {
    'add-lte':               {'module':'fwtranslate_add_lte',    'api':'add_lte'},
    'remove-lte':            {'module':'fwtranslate_revert',     'api':'revert'},    
}

class FWSYSTEM_API:
    """This class implements fwagent level APIs of flexiEdge device.
       Typically these APIs are used to monitor various components of flexiEdge.
       They are invoked by the flexiManage over secure WebSocket
       connection using JSON requests.
       For list of available APIs see the 'fwsystem_translators' variable.
    """
    def __init__(self):
        """Constructor method
        """
        self.request_executer = FwRequestExecuter(fwsystem_modules, fwsystem_translators, fwglobals.g.system_cfg)

    def call(self, request):
        try:
            req = request['message']      

            # Translate request to list of commands to be executed
            cmd_list = self.request_executer.translate(request)

            self.request_executer.execute(request, cmd_list)
            executed = True

            # Save successfully handled configuration request into database.
            try:
                fwglobals.g.system_cfg.update(request, cmd_list, executed)
            except Exception as e:
                self.request_executer.revert(cmd_list)
                raise e

        except Exception as e:
            err_str = "FWSYSTEM_API::call: %s" % str(traceback.format_exc())
            fwglobals.log.error(err_str)
            raise e

        return {'ok':1}

    def restore_system_configuration(self):
        """Restore system configuration.
        Run all system configuration translated commands.
        """
        try:
            fwglobals.log.info("===restore system configuration: started===")

            system_requests = fwglobals.g.system_cfg.dump(keys=True)
            if system_requests:
                for req in system_requests:
                    reply = fwglobals.g.handle_request(req)
                
            return True
        except Exception as e:
            fwglobals.log.excep("restore_system_configuration: %s" % str(e))

        fwglobals.log.info("====restore system configuration: finished===")
        return True