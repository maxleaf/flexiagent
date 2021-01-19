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

import hashlib
import json
import os
import re
import traceback
import yaml
import copy

from sqlitedict import SqliteDict

import fwglobals
import fwrouter_api
import fwutils


class FwRouterCfg:
    """This is requests DB class representation.

    :param db_file: SQLite DB file name.
    """
    def __init__(self, db_file):
        """Constructor method
        """
        self.db_filename = db_file
        self.db = SqliteDict(db_file, autocommit=True)

        if self.db.get('signature') is None:
            self.db['signature'] = ""

        self.callbacks = []


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        self.db.close()

    def register_callback(self, listener, callback, requests):
        """Registers a listener for notifications about  requests stored in /
        removed from the configuration database. The latest is done by the
        FwRouterCfg::update() method. It invokes the 'callback' before
        the request is saved in the database.
        The callback signature should be (req, params) where 'req' is the
        request name, e.g. 'add-tunnel', and the 'params' are the parameters of
        the request as they would received from server in 'params' field.

        :param: listener - name of the listener for logging propuses.
        :param: callback - the function to be used to notify listener of request
        :param: requests - list of requests the listener would like to be
                           notified for, e.g.:
                            ['add-interface', 'remove-interface', 'stop-router']
        """
        fwglobals.log.debug("FwRouterCfg: register_callback: %s.%s(%s)"\
            %(listener, callback.__name__, str(requests)))
        elem = {'listener':listener, 'callback': callback, 'requests':requests}
        self.callbacks.append(elem)

    def unregister_callback(self, listener, callback):
        """Unregisters a listener from listening on incoming requests
        :param: listener - string representing the module. For logging.
        :param: callback - the callback used to listen to requests.
        """
        for (idx, elem) in enumerate(self.callbacks):
            if elem['callback'] == callback:
                fwglobals.log.debug("unregister_callbacks_pre_update: %s::%s" \
                    %(listener, callback.__name__))
                del self.callbacks[idx]
                return

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for req_key in self.db:
            del self.db[req_key]

        # Reset configuration to the value, that differs from one calculated
        # by the flexiManage. This is to enforce flexiManage to issue 'sync-device'
        # in order to fill the configuration database again with most updated
        # configuration.
        #
        self.reset_signature("empty_router_cfg", log=False)

    def _get_request_key(self, request):
        """Generates uniq key for request out of request name and
        request parameters. To do that uses the get_request_key() function
        that MUST be defined in the correspondent translator file,
        e.g. fwtranslate_add_tunnel.py.

        !IMPORTANT!  keep this function internal! No one should be aware of
                     database implementation. If you feel need to expose this
                     function, please consider to add API to this class
                     that encapsulates the needed functionality!
        """
        req     = request['message']
        params  = request.get('params')

        # add-/remove-/modify-X requests use key function defined for 'add-X'.
        # start-router & stop-router break add-/remove-/modify- convention.
        if req=='start-router' or req=='stop-router':
            src_req = 'start-router'
        else:
            src_req = re.sub(r'^\w+', 'add', req)
        key_module  = fwrouter_api.fwrouter_modules.get(fwrouter_api.fwrouter_translators[src_req]['module'])
        key_func    = getattr(key_module, 'get_request_key')
        return key_func(params)

    def _call_callback(self, listeners, req_name, params):
        """
        go over callback data base and check if callback should be called for each listener
        based on the request name. This function is called from update().
        """
        for elem in listeners:
            if req_name in elem['requests']:
                fwglobals.log.debug("FwRouterCfg: %s.%s(%s) - before"\
                        %(elem['listener'], elem['callback'].__name__, req_name))

                try:
                    elem['callback'](req_name, params)
                except Exception as e:
                    fwglobals.log.error("FwRouterCfg: %s.%s(%s): %s"\
                            %(elem['listener'], elem['callback'].__name__, req_name, str(e)))
                    pass

                fwglobals.log.debug("FwRouterCfg: %s.%s(%s) - after"\
                        %(elem['listener'], elem['callback'].__name__, req_name))

    def update(self, request, cmd_list=None, executed=False, whitelist=None):
        """Save configuration request into DB.
        The 'add-X' configuration requests are stored in DB, the 'remove-X'
        requests are not stored but remove the correspondent 'add-X' requests.

        :param request:     The request received from flexiManage.
        :param cmd_list:    List of commands to be executed in order to fullfil
                            configuration request. The command can invoke VPP API,
                            run Linux shell commands, update internal agent objects,
                            etc. They are generated by generated by translation.
        :param executed:    The 'executed' flag - True if the configuration
                            request was translated and executed, False if it was
                            translated but was not executed.
        :param whitelist:   White list of parameters allowed to be modified.
        :returns: None.
        """
        req     = request['message']
        params  = request.get('params')
        req_key = self._get_request_key(request)

        try:
            cb_params = params if re.match('(add-|start-router)', req) else self.db[req_key]['params']
            self._call_callback(self.callbacks, req, cb_params)

            if re.match('add-', req) or re.match('start-router', req):
                self.db[req_key] = { 'request' : req , 'params' : params , 'cmd_list' : cmd_list , 'executed' : executed }
            elif re.match('modify-interface|modify-tunnel', req):
                entry = self.db[req_key]
                entry.update({'params' : params})
                self.db[req_key] = entry  # Can't update self.db[req_key] directly, sqldict will ignore such modification
            elif re.match('modify-', req):
                entry = self.db[req_key]
                for key, value in params.items():
                    if isinstance(value, dict):
                        for key2, value2 in value.items():
                            if key2 in whitelist:
                                entry['params'][key][key2] = value2
                self.db[req_key] = entry  # Can't update self.db[req_key] directly, sqldict will ignore such modification
            else:
                del self.db[req_key]

        except KeyError:
            pass
        except Exception as e:
            fwglobals.log.error("FwRouterCfg.update(%s) failed: %s, %s" % \
                        (req_key, str(e), str(traceback.format_exc())))
            raise Exception('failed to update request database')


    def get_request_params(self, request):
        """Retrives parameters of the request as they are stored in DB.
        I know that it sounds weired, as request includes parameters in 'params'
        field :) This is hack. We use this function to retrieve parameters
        of the 'add-X' requests stored in DB, when the provided request is
        correspondent 'remove-X'.
        Note:
            - the 'remove-X' requests are not stored in DB
            - the 'remove-X' 'params' is a subset of the 'add-X' 'params',
              which is sufficient to generate DB key.

        :param request:         The name of the 'remove-X' request, e.g. 'remove-tunnel'.
        :param params:      The parameters of the 'remove-X' request.

        :returns: the parameters of the correspondent 'add-X' request.
        """
        req_key = self._get_request_key(request)
        if not req_key in self.db:
            return None
        return self.db[req_key].get('params')

    def get_request_cmd_list(self, request):
        """Retrives translation of the request to list of commands.

        :param request: The request as it would be received on network,
                        including name (request['message']) and parmateres
                        (request['params']) if exist.

        :returns: the tuple of the command list and the 'executed' flag
        """
        req_key = self._get_request_key(request)
        if not req_key in self.db:
            return (None, None)
        return (self.db[req_key].get('cmd_list'), self.db[req_key].get('executed'))

    def exists(self, request):
        """Check if entry exists in DB.

        :param request: the configuration request as it would be received from flexiManage

        :returns: 'True' if request exists and 'False' otherwise.
        """
        req_key = self._get_request_key(request)
        res = True if req_key in self.db else False
        return res

    def get_params(self, request):
        """Retrives parameters of the provided configuration request.
        This function can be used to find parameters of configuration item
        before modification.

        :param request: The configuration request, e.g. modify-interface.
        :returns: parameters of the request stored in the database.
        """
        req_key = self._get_request_key(request)
        if req_key in self.db:
            return self.db[req_key].get('params')
        return None

    def is_same_cfg_item(self, request1, request2):
        """Checks if provided requests stand for the same configuration item.
        """
        req_key1 = self._get_request_key(request1)
        req_key2 = self._get_request_key(request2)
        if req_key1 == req_key2:
            return True
        return False

    def dump(self, types=None, escape=None, full=False, keys=False):
        """Dumps router configuration into list of requests that look exactly
        as they would look if were received from server.

        Note the dump order of configuration requests follows oreder of request
        types in 'types' argument.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        :param keys:   return requests with request key used by DB to identify request.

        :returns: list of configuration requests stored in DB.
        """
        if not types:
            types = [
                'start-router',
                'add-interface',
                'add-tunnel',
                'add-route',		# routes should come after tunnels, as they might use them
                'add-dhcp-config',
                'add-application',
                'add-multilink-policy'
            ]
        if escape:
            for t in escape:
                types.remove(t)

        # The dump is O(num_types x n) - improve that on demand!
        cfg     = []
        db_keys = sorted(self.db.keys())  # The key order might be affected by dictionary content, so sort it
        for req in types:
            for key in db_keys:
                if re.match(req, key):
                    request = {
                        'message': self.db[key].get('request',""),
                        'params':  self.db[key].get('params', "")
                    }
                    if request['params'] == None:  # flexiManage team doesn't like None :)
                        request['params'] = {}
                    if full:
                        request.update({
                            'cmd_list': self.db[key].get('cmd_list', ""),
                            'executed': self.db[key].get('executed', "")})
                    if keys:
                        request.update({'key': key})
                    cfg.append(request)
        return cfg

    def dumps(self, types=None, escape=None, full=False):
        """Dumps router configuration into printable string.

        :param types:  list of types of configuration requests to be dumped, e.g. [ 'add-interface' , 'add-tunnel' ]
        :param escape: list of types of configuration requests that should be escaped while dumping
        :param full:   return requests together with translated commands.
        """
        sections = {                # Use stairway to ensure section order in
                                    # output string created by json.dumps()
                                    #
            'start-router':         "======= START COMMAND =======",
            'add-interface':        "======== INTERFACES ========",
            'add-route':            "========= ROUTES =========",
            'add-tunnel':           "========== TUNNELS ==========",
            'add-dhcp-config':      "=========== DHCP CONFIG ===========",
            'add-application':      "============ APPLICATIONS ============",
            'add-multilink-policy': "============= POLICIES ============="
        }

        out = {}
        prev_msg = { 'message': 'undefined' }

        cfg = self.dump(types=types, escape=escape, full=full, keys=True)
        for msg in cfg:
            # Add new section
            if msg['message'] != prev_msg['message']:
                prev_msg['message'] = msg['message']
                section_name = sections[msg['message']]
                out[section_name] = []

            # Add configuration item to section
            item = {
                'Key':    msg['key'],
                'Params': msg['params']
            }
            if full:
                item.update({'Executed': str(msg['executed'])})
                item.update({'Commands': fwutils.yaml_dump(msg['cmd_list']).split('\n')})
            out[section_name].append(item)
        if not out:
            return ''
        return json.dumps(out, indent=2, sort_keys=True)

    def _get_requests(self, req):
        """Retrives list of configuration requests parameters for requests with
        the 'req' name.
        This is generic function wrapped by request specific one-line APIs,
        like get_tunnels().

        :param req:         The request name, e.g. 'add-tunnel'.
        :returns: list of request parameters.
        """
        requests = []
        for key in self.db:
            if re.match(req, key):
                requests.append(self.db[key]['params'])
        return requests

    def get_interfaces(self, type=None, pci=None, ip=None):
        interfaces = self._get_requests('add-interface')
        if not type and not pci and not ip:
            return interfaces
        result = []
        for params in interfaces:
            if type and not re.match(type, params['type'], re.IGNORECASE):
                continue
            elif pci and pci != params['pci']:
                continue
            elif ip and not re.match(ip, params['addr']):
                continue
            result.append(params)
        return result

    def get_tunnels(self):
        return self._get_requests('add-tunnel')

    def get_tunnel(self, tunnel_id):
        key = 'add-tunnel:%d' % (tunnel_id)
        if key in self.db:
            return self.db[key].get('params')
        return None

    def get_multilink_policy(self):
        if 'add-multilink-policy' in self.db:
            return self.db['add-multilink-policy']['params']
        return None

    def get_applications(self):
        if 'add-application' in self.db:
            return self.db['add-application']['params']
        return None

    def get_wan_interface_gw(self, ip):
        import fwutils
        interfaces = self.get_interfaces(type='wan', ip=ip)
        if not interfaces:
            return (None, None)
        pci = interfaces[0]['pci']
        gw  = interfaces[0].get('gateway')
        # If gateway not exist in interface configuration, use default
        # This is needed when upgrading from version 1.1.52 to 1.2.X
        if not gw:
            tap = fwutils.pci_to_tap(pci)
            rip, _ = fwutils.get_interface_gateway(tap)
            return pci, rip
        else:
            return pci, gw

    def update_signature(self, request):
        """Updates the database signature.
        This function assists the database synchronization feature that keeps
        the configuration set by user on the flexiManage in sync with the one
        stored on the flexiEdge device.
            The initial signature of the database is empty string. Than on every
        successfully handled request it is updated according following formula:
                signature = sha1(signature + request)
        where both signature and delta are strings.

        :param request: the last successfully handled router configuration
                        request, e.g. add-interface, remove-tunnel, etc.
                        As configuration database signature should reflect
                        the latest configuration, it should be updated with this
                        request.
        """
        current     = self.db['signature']
        delta       = json.dumps(request, separators=(',', ':'), sort_keys=True)
        hash_object = hashlib.sha1(current + delta)
        new         = hash_object.hexdigest()

        self.db['signature'] = new
        fwglobals.log.debug("fwrouter_cfg: sha1: new=%s, current=%s, delta=%s" %
                            (str(new), str(current), str(delta)))

    def get_signature(self):
        """Retrives signature of the current configuration.
        The signature is SHA-1 based hash on requests store in local database.

        :returns: the signature as a string.
        """
        if not 'signature' in self.db:
            self.reset_signature()
        return self.db['signature']

    def reset_signature(self, new_signature=None, log=True):
        """Resets configuration signature to the empty sting.

        :param new_signature: string to be used as a signature of the configuration.
                        If not provided, the empty string will be used.
                        When flexiManage detects discrepancy between this signature
                        and between signature that it calculated, it sends
                        the 'sync-device' request in order to apply the user
                        configuration onto device. On successfull sync the signature
                        is reset to the empty string on both sides.
        :param log: if False the reset will be not logged.
        """
        old_signature = self.db.get('signature', '<none>')
        new_signature = "" if new_signature == None else new_signature
        self.db['signature'] = new_signature
        if log:
            fwglobals.log.debug("fwrouter_cfg: reset signature: '%s' -> '%s'" % \
                                (old_signature, new_signature))

    def get_sync_list(self, requests):
        """Intersects requests provided within 'requests' argument against
        the requests stored in the local database and generates output list that
        can be used for synchronization of router configuration. This output list
        is called sync-list. It includes sequence of 'remove-X', 'modify-X' and
        'add-X' requests that should be applied to device in order to configure
        it with the configuration, reflected in the input list 'requests'.

        :param requests: list of requests that reflects the desired configuration.
                         The requests are in formant of flexiManage<->flexiEdge
                         message: { 'message': 'add-X', 'params': {...}}.

        :returns: synchronization list - list of 'remove-X', 'modify-X' and
                         'add-X' requests that takes device to the desired
                         configuration if applied to the device.
        """

        # Firstly we hack a little bit the input list as follows:
        # build dictionary out of this list where values are list elements
        # (requests) and keys are request keys that local database would use
        # to store these requests. Accidentally these are exactly same keys
        # dumped by fwglobals.g.router_cfg.dump() used below ;)
        #
        input_requests = {}
        for request in copy.deepcopy(requests): # Use deepcopy as we might modify input_requests[key] below
            key = self._get_request_key(request)
            input_requests.update({key:request})

        # Now dump local configuration in order of 'remove-X' list.
        # We will go over dumped requests and filter out requests that present
        # in the input list and that have same parameters. They correspond to
        # configuration items that should be not touched by synchronization.
        # The dumped requests that present in the input list but have different
        # parameters stand for modifications.
        #
        dumped_requests = fwglobals.g.router_cfg.dump(keys=True)
        output_requests = []

        for dumped_request in dumped_requests:
            dumped_key = dumped_request['key']
            if dumped_key in input_requests:
                # The configuration item presents in the input list.
                #
                dumped_params = dumped_request.get('params')
                input_params  = input_requests[dumped_key].get('params')
                if fwutils.compare_request_params(dumped_params, input_params):
                    # The configuration item has exactly same parameters.
                    # It does not require sync, so remove it from input list.
                    #
                    del input_requests[dumped_key]
                else:
                    # The configuration item should be modified.
                    # Rename requests in input list with 'modify-X'.
                    #
                    # At this stage only 'modify-interface' is supported,
                    # so for the rest types of configuration items we add
                    # the correspondent 'remove-X' request with current
                    # parameters to the output list and later in this function
                    # we will add the 'add-X' request from the input list.
                    #
                    if dumped_request['message'] == 'add-interface':
                        input_requests[dumped_key]['message'] = 'modify-interface'
                    else:
                        dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                        output_requests.append(dumped_request)
            else:
                # The configuration item does not present in the input list.
                # So it stands for item to be removed. Add correspondent request
                # to the output list.
                # Ignore 'start-router', 'stop-router', etc as they are not
                # an configuration items.
                #
                if not re.search('(start|stop)-router', dumped_request['message']):
                    dumped_request['message'] = dumped_request['message'].replace('add-', 'remove-')
                    output_requests.append(dumped_request)


        # At this point the input list includes 'add-X' requests that stand
        # for new or for modified configuration items.
        # Just go and add them to the output list 'as-is'.
        #
        output_requests += input_requests.values()

        return output_requests
