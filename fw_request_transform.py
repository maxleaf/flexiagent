'''
Request transformation framework - It transforms requests based on 'self.request_transform_rules'
configured in a JSON structure.

Input:
    - Existing executed request cache (FcCfgDatabase instance)
    - New request list (Received aggregated or simple request list)
    - A dict argument containing values that represent the agent state which can be used in
      making the required transform decisions

Output:
    - Transformed request list
    - Extracted info as configired in request rules which can be used for further triggers

The framework provides below functions
(1) Suppress no-op requests
(2) Substitution - This takes care of 'replace' and 'pre' and 'post' substitutions
    (2.1) Replace has option to construct request from config cache or from new-requests
    (2.2) Pre-Processing and Post-processing shall construct new requests with params that can be
        looked up using the request-key in the
        - Current state of Config cache (executed requests)
        - The current aggregated requests list being worked on
        - From the current specific request being transformed
        Pre and Post processing includes an on-condition-function which if provided shall be
        validated before adding the pre and post processing requests
(3) Duplicate suppression
    (3.1) Provision to remove earlier requests which would become no-op due to this request add
    (3.2) Provision to retain first_in_order or last_in_order in case of duplicates
(4) Builds user configured output_info extracted from the requests for making further decisions
    like if restart required or not etc..
    (4.1) Returns a dict with param names as key
    (4.2) On duplicate param, It is added as a value to the same key - values are returned as arrays
    (4.3) Output info can be added either as values or from results of function attribute configured
    output_info = {
        'key1' : [value1, value2]
        'key2' : [value1, value2]
    }


Notes:
- Messages not defined in transform rules will be executed as is - No changes in content or position
- Incoming message order shall not be changed. Except if it falls in scope of duplicate suppression

Pre-conditions:
** Ensure the config rules does not have circular dependency in pre and post processing rules
'''

import copy
import json
import fwglobals
import fwutils


class Fw_Request_Transformer:

    def __init__(self, config_db, request, state_params):
        self.config_db = config_db
        if request['message'] == 'aggregated':
            self.request_list = request['params']['requests']
        else:
            self.request_list = [request]
        with open('/etc/flexiwan/agent/request_transform_rules.json', 'r') as config:
            self.request_transform_rules = json.load(config)
        self.state_params = state_params

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return


    def __fw_request_add_param_by_request_key(self, request_key_param, add_request,
            transforming_request, transforming_request_list):

        params = None
        if request_key_param.get('find-in-transforming-request'):
            if transforming_request.get('params'):
                params = copy.deepcopy(transforming_request.get('params'))
        elif request_key_param.get('find-in-request-list'):
            for request in transforming_request_list:
                if add_request['message'] == request['message']:
                    params = copy.deepcopy(request.get('params'))
        else:
            if request_key_param.get('find-in-cache-using-transforming-request'):
                check_request = {
                    'message': add_request['message'],
                    'params': transforming_request.get('params')
                }
                config_db_params = self.config_db.get_request_params(check_request)
            else:
                config_db_params = self.config_db.get_request_params(add_request)
            if config_db_params:
                params = copy.deepcopy(config_db_params)                                

        return params


    def __fw_request_construct(self, request, transforming_request, transforming_request_list):

        fwglobals.log.debug("Request Transformer - Constructing message: %s" % (request['message']))
        add_params = request.get('add-params')
        if add_params is None:
            return copy.deepcopy(request)

        out = {}
        out['message'] = request['message']
        by_request_key_list = add_params.get('by-request-key')
        if by_request_key_list:
            for request_key_param in by_request_key_list:
                params = self.__fw_request_add_param_by_request_key(request_key_param,
                    request, transforming_request, transforming_request_list)
                if params:
                    out['params'] = params
                else:
                    fwglobals.log.debug("Request Transformer - Params not found: %s" %
                        request_key_param)
                    return None
        return out


    def __fw_request_process_dependencies(self, request, transformed_request_list):
        ''' Handles dependencies section of transform rules
        '''
        #fetch transform rules
        rules = self.request_transform_rules.get(request.get('message'))
        if rules is None:
            transformed_request_list.append(request)
            return
        dependencies = rules.get('dependencies')
        if dependencies is None:
            transformed_request_list.append(request)
            return

        pre_process_rules = dependencies.get('pre-processing')
        if pre_process_rules:
            on_condition_function = pre_process_rules.get('on-condition-function')
            if on_condition_function:
                function  = getattr(Fw_Request_Transformer, on_condition_function)
                execute_pre_process = function(self.state_params)
            else:
                execute_pre_process = True
            if execute_pre_process:
                pre_process_request_list = pre_process_rules.get('requests')
                for pre_process_request in pre_process_request_list:
                    add_request = self.__fw_request_construct(pre_process_request, request,
                        transformed_request_list)
                    if add_request:
                        self.__fw_request_process_dependencies(add_request,
                                transformed_request_list)

        replace_as_list = dependencies.get('replace-as')
        if replace_as_list:
            for replace_as in replace_as_list:
                add_request = self.__fw_request_construct(replace_as, request,
                    transformed_request_list)
                if add_request:
                    self.__fw_request_process_dependencies(add_request, transformed_request_list)
        else:
            # Completed re-processing - Add self
            transformed_request_list.append(request)

        post_process_rules = dependencies.get('post-processing')
        if post_process_rules:
            on_condition_function = pre_process_rules.get('on-condition-function')
            if on_condition_function:
                function  = getattr(Fw_Request_Transformer, on_condition_function)
                execute_post_process = function(self.state_params)
            else:
                execute_post_process = True
            if execute_post_process:
                post_process_request_list = post_process_rules.get('requests')
                for post_process_request in post_process_request_list:
                    add_request = self.__fw_request_construct(post_process_request,
                        request, transformed_request_list)
                    if add_request:
                        self.__fw_request_process_dependencies(add_request,
                                transformed_request_list)


    def __fw_request_supress_duplicates(self, request, transformed_request_list):

        duplicate_supress_rule = self.request_transform_rules.get(request.get('message'))
        if duplicate_supress_rule:
            remove_previous_list = duplicate_supress_rule.get('remove-previous-requests')
            if remove_previous_list:
                for remove_previous in remove_previous_list:
                    for transformed_request in transformed_request_list:
                        remove_request = self.__fw_request_construct(remove_previous, request,
                            transformed_request_list)
                        if remove_request == transformed_request:
                            transformed_request_list.remove(transformed_request)
            retain_order = duplicate_supress_rule.get('retain_order')
            if retain_order:
                if retain_order == 'first_in_order':
                    first_in_order_seen = False
                    for transformed_request in transformed_request_list:
                        if transformed_request == request:
                            if first_in_order_seen:
                                transformed_request_list.remove(transformed_request)
                            else:
                                first_in_order_seen = True
                    if first_in_order_seen is False:
                        transformed_request_list.append(request)
                elif retain_order == 'last_in_order':
                    transformed_request_list.append(request)
                    last_in_order_seen = False
                    for transformed_request in reversed(transformed_request_list):
                        if transformed_request == request:
                            if last_in_order_seen:
                                transformed_request_list.remove(transformed_request)
                            else:
                                last_in_order_seen = True
            else:
                transformed_request_list.append(request)
        else:
            transformed_request_list.append(request)


    def __fw_request_extract_output_info(self, request, output_info):
        add_to_output = request.get('add-to-output')
        if add_to_output:
            as_value_list = add_to_output.get('as-value')
            for as_value in as_value_list:
                if output_info.get(as_value['add-name']):
                    output_info[as_value['add-name']].append(as_value['value'])
                else:
                    output_info[as_value['add-name']] = [as_value['value']]

            by_function_list = add_to_output.get('by-function')
            for by_function in by_function_list:
                function  = getattr(Fw_Request_Transformer, by_function['function'])
                function_out = function(request)
                if output_info.get(by_function['add-name']):
                    output_info[by_function['add-name']].append(function_out)
                else:
                    output_info[by_function['add-name']] = function_out


    def __fw_check_reconnect_agent_on_modify_interface(self, request):
        new_params = request.get('params')
        old_params = self.config_db.get_interfaces(dev_id=new_params['dev_id'])[0]
        if new_params.get('addr') and new_params.get('addr') != old_params.get('addr'):
            return True
        if new_params.get('gateway') != old_params.get('gateway'):
            return True
        if new_params.get('metric') != old_params.get('metric'):
            return True
        return False


    def __fw_get_gateway_param_in_modify_interface(self, request):
        return request['params'].get('gateway')


    def __fw_is_router_state_stopped(self, args):
        return args.get('is_router_state_stopped', False)


    def __fw_is_vpp_running(self, args, part_of_aggregate):
        if part_of_aggregate is False:
            return args.get('is_vpp_running', False)
        return None


    def __fw_check_noop_request(self, request):

        transform_rules = self.config_db.request_transform_rules.get(request['message'])

        # Call custom noop function checks provided in transform rules
        noop_function_check = transform_rules.get('noop-check-function')
        if noop_function_check:
            function  = getattr(Fw_Request_Transformer, noop_function_check)
            return function(request)

        # Check if it matches existing request
        old_params = self.config_db.get_request_params(request)
        if old_params:
            if fwutils.compare_request_params(request.get('params'), old_params):
                return True
        return False

    def fw_log_requests(self, request_list, log_info):
        for request in request_list:
            #fwglobals.log.debug("Request Transformer %s: Request: %s" % (log_info, request))
            fwglobals.log.debug("Request Transformer %s: Name: %s Key: %s" %
            (log_info, request['message'], self.config_db._get_request_key(request)))


    def fw_transform_request(self):
        self.fw_log_requests(self.request_list, "Received message")

        if len(self.request_list) == 1:
            if self.__fw_check_noop_request(self.request_list[0]):
                fwglobals.log.debug("Message ignore by noop processing")
                return None, None

        self.fw_log_requests(self.request_list, "Post Noop processing")

        post_dependency_process_list = []
        for request in self.request_list:
            self.__fw_request_process_dependencies(request, post_dependency_process_list)

        self.fw_log_requests(post_dependency_process_list, "Post dependency processing")

        post_duplicate_process_list = []
        for request in post_dependency_process_list:
            self.__fw_request_supress_duplicates(request, post_duplicate_process_list)

        self.fw_log_requests(post_duplicate_process_list, "Post duplicate supressing")

        output_info = {}
        for request in post_duplicate_process_list:
            self.__fw_request_extract_output_info(request, output_info)

        fwglobals.log.debug("Extracted message info: %s" % (output_info))

        if (len(post_duplicate_process_list) > 1):
            aggregated_message = {}
            aggregated_message['message'] = 'aggregated'
            aggregated_message['params'] = {}
            aggregated_message['params']['requests'] = post_duplicate_process_list
            return aggregated_message, output_info
        else:
            return post_duplicate_process_list[0], output_info