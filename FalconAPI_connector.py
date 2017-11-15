# --
# File: FalconAPI_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom App imports
import phantom.app as phantom
import phantom.utils as util
import json

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from FalconAPI_consts import *

import requests
from collections import defaultdict


# Define the App Class
class FalconHostAPI(BaseConnector):

    def __init__(self):
        """ """
        # Call the BaseConnectors init first
        super(FalconHostAPI, self).__init__()

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        config = self.get_config()

        # Get the Base URL from the asset config and so some cleanup
        self._base_url = config[FALCONAPI_BASE_URL]

        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        # The host member extacts the host from the URL, is used in creating status messages
        self._host = self._base_url[self._base_url.find('//') + 2:]

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Content-Type': 'application/json'}

        user = config[FALCONAPI_USER]
        key = config[FALCONAPI_KEY]

        self._auth = (user, key)

        return phantom.APP_SUCCESS

    def _parse_errors(self, resp_json, status_code, action_result, fof_ok):

        error = resp_json['errors'][0]

        code = error.get('code', 'Unknown')
        message = error.get('message', 'message')

        phantom_status = phantom.APP_ERROR

        if ((code == 404) and (fof_ok)):
            phantom_status = phantom.APP_SUCCESS

        return action_result.set_status(phantom_status, FALCONAPI_ERR_FROM_SERVER.format(status=code, detail=message))

    def _call_falcon_api(self, endpoint, action_result, headers={}, params=None, data=None, method="get", fof_ok=False):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers """

        # Get the config
        config = self.get_config()

        # Create the headers
        headers.update(self._headers)

        resp_json = None

        # get or post or put, whatever the caller asked us to use, if not specified the default will be 'get'
        request_func = getattr(requests, method.lower())

        # handle the error in case the caller specified a non-existant method
        if (not request_func):
            return (action_result.set_status(phantom.APP_ERROR, FALCONAPI_ERR_API_UNSUPPORTED_METHOD, method=method), None)

        # Make the call
        try:
            r = request_func(self._base_url + endpoint,  # The complete url is made up of the base_url, the api url and the endpiont
                    auth=self._auth,  # The authentication method, currently set to simple base authentication
                    data=json.dumps(data) if data else None,  # the data, converted to json string format if present, else just set to None
                    headers=headers,  # The headers to send in the HTTP call
                    verify=config[phantom.APP_JSON_VERIFY],  # should cert verification be carried out?
                    params=params)  # uri parameters if any
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, FALCONAPI_ERR_SERVER_CONNECTION, e), resp_json)

        action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if ('application/json' in r.headers['Content-Type']):

            # Try a json parse, since most REST API's give back the data in json, if the device does not return JSONs, then need to implement parsing them some other manner
            try:
                resp_json = r.json()
            except Exception as e:
                # r.text is guaranteed to be NON None, it will be empty, but not None
                msg_string = FALCONAPI_ERR_JSON_PARSE.format(raw_text=r.text)
                return (action_result.set_status(phantom.APP_ERROR, msg_string, e), resp_json)

            if ( resp_json.get('errors', [])):
                self._parse_errors(resp_json, r.status_code, action_result, fof_ok)
                return (action_result.get_status(), resp_json)
        else:
            return (action_result.set_status(phantom.APP_ERROR, "Response from server not a JSON"), r.text)

        # Handle any special HTTP error codes here, many devices return an HTTP error code like 204. The requests module treats these as error,
        # so handle them here before anything else, uncomment the following lines in such cases
        # if (r.status_code == 201):
        #     return (phantom.APP_SUCCESS, resp_json)

        # Handle/process any errors that we get back from the device
        if (200 <= r.status_code <= 399):
            # Success
            return (phantom.APP_SUCCESS, resp_json)

        details = json.dumps(resp_json).replace('{', '').replace('}', '')

        return (action_result.set_status(phantom.APP_ERROR, FALCONAPI_ERR_FROM_SERVER.format(status=r.status_code, detail=details)), resp_json)

    @staticmethod
    def _get_hash_type(hash_value, action_result):

        if util.is_md5(hash_value):
            return (phantom.APP_SUCCESS, "md5")

        if util.is_sha1(hash_value):
            return (phantom.APP_SUCCESS, "sha1")

        if util.is_sha256(hash_value):
            return (phantom.APP_SUCCESS, "sha256")

        return (action_result.set_status(phantom.APP_ERROR, FALCONAPI_ERR_UNSUPPORTED_HASH_TYPE), None)

    def _get_ioc_type(self, ioc, action_result):

        if util.is_ip(ioc):
            return (phantom.APP_SUCCESS, "ipv4")

        if util.is_hash(ioc):
            return FalconHostAPI._get_hash_type(ioc, action_result)

        if util.is_domain(ioc):
            return (phantom.APP_SUCCESS, "domain")

        return action_result.set_status(phantom.APP_ERROR, "Failed to detect the IOC type")

    def _get_device_count(self, params, action_result):

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_DEVICE_COUNT_APIPATH, action_result, params=params, fof_ok=True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        try:
            resources = response['resources']
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response", e)

        if (not resources):
            action_result.update_summary({'device_count': 0})
            return action_result.set_status(phantom.APP_SUCCESS)

        result = resources[0]

        # successful request
        action_result.update_summary({'device_count': result.get('device_count', 0)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_devices_ran_on(self, ioc, ioc_type, param, action_result):

        api_data = {
            "type": ioc_type,
            "value": ioc
        }

        count_only = param.get(FALCONAPI_JSON_COUNT_ONLY, False)

        if (count_only):
            return self._get_device_count(api_data, action_result)

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_DEVICES_RAN_ON_APIPATH, action_result, params=api_data, fof_ok=True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # successful request / "none found"
        for d in response["resources"]:
            action_result.add_data({"device_id": d})
        action_result.set_summary({"device_count": len(response["resources"])})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_get_process_detail(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        fpid = param[FALCONAPI_GET_PROCESS_DETAIL_FALCON_PROCESS_ID]

        api_data = {
            "ids": fpid
        }

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_PROCESS_DETAIL_APIPATH, action_result, params=api_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # successful request
        data = dict(response["resources"][0])
        action_result.add_data(data)

        action_result.update_summary({ 'device_id': data.get('device_id', ''), 'file_name': data.get('file_name', '')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_get_device_detail(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        fdid = param[FALCONAPI_GET_DEVICE_DETAIL_FALCON_DEVICE_ID]

        api_data = {
            "ids": fdid
        }

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_DEVICE_DETAIL_APIPATH, action_result, params=api_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # successful request
        data = dict(response["resources"][0])
        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_upload_iocs(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        # required parameters
        ioc = param[FALCONAPI_JSON_IOC]
        policy = param[FALCONAPI_UPLOAD_IOCS_POLICY]

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        api_data = {
                "value": ioc,
                "type": ioc_type,
                "policy": policy}

        # optional parameters
        api_data["share_level"] = param.get(FALCONAPI_UPLOAD_IOCS_SHARE_LEVEL, 'red')
        if FALCONAPI_UPLOAD_IOCS_EXPIRATION in param:
            api_data["expiration_days"] = int(param[FALCONAPI_UPLOAD_IOCS_EXPIRATION])
        if FALCONAPI_UPLOAD_IOCS_SOURCE in param:
            api_data["source"] = param[FALCONAPI_UPLOAD_IOCS_SOURCE]
        if FALCONAPI_UPLOAD_IOCS_DESCRIPTION in param:
            api_data["description"] = param[FALCONAPI_UPLOAD_IOCS_DESCRIPTION]

        ret_val, response = self._call_falcon_api(FALCONAPI_UPLOAD_IOCS_APIPATH, action_result, data=[api_data], method="POST")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "IOC Uploaded to create alert")

    def _action_get_alert(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[FALCONAPI_JSON_IOC]
        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        api_data = {"ids": "{0}:{1}".format(ioc_type, ioc)}

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_IOCS_APIPATH, action_result, params=api_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # successful request
        data = dict(response["resources"][0])

        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS, FALCONAPI_SUCC_GENERAL)

    def _action_update_iocs(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[FALCONAPI_JSON_IOC]
        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        api_data = {"ids": "{0}:{1}".format(ioc_type, ioc)}

        update_data = {}

        # optional parameters
        if FALCONAPI_UPDATE_IOCS_POLICY in param:
            update_data["policy"] = param[FALCONAPI_UPDATE_IOCS_POLICY]
        if FALCONAPI_UPDATE_IOCS_SHARE_LEVEL in param:
            update_data["share_level"] = param[FALCONAPI_UPDATE_IOCS_SHARE_LEVEL]
        if FALCONAPI_UPDATE_IOCS_EXPIRATION in param:
            update_data["expiration_days"] = int(param[FALCONAPI_UPDATE_IOCS_EXPIRATION])
        if FALCONAPI_UPDATE_IOCS_SOURCE in param:
            update_data["source"] = param[FALCONAPI_UPDATE_IOCS_SOURCE]
        if FALCONAPI_UPDATE_IOCS_DESCRIPTION in param:
            update_data["description"] = param[FALCONAPI_UPDATE_IOCS_DESCRIPTION]

        ret_val, response = self._call_falcon_api(FALCONAPI_UPDATE_IOCS_APIPATH, action_result, data=update_data, method="PATCH", params=api_data)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, FALCONAPI_SUCC_GENERAL)

    def _action_delete_iocs(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[FALCONAPI_JSON_IOC]
        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        api_data = {"ids": "{0}:{1}".format(ioc_type, ioc)}

        ret_val, response = self._call_falcon_api(FALCONAPI_DELETE_IOCS_APIPATH, action_result, params=api_data, method="DELETE")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, FALCONAPI_SUCC_GENERAL)

    def _action_search_iocs(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        api_data = {
            "limit": 400  # 500 is the max, don't want to give max, this could be tuned
        }

        # optional parameters
        if FALCONAPI_JSON_IOC in param:
            api_data["values"] = [param[FALCONAPI_JSON_IOC]]
        if FALCONAPI_SEARCH_IOCS_POLICY in param and param[FALCONAPI_SEARCH_IOCS_POLICY] != "all":
            api_data["policies"] = [param[FALCONAPI_SEARCH_IOCS_POLICY]]
        if FALCONAPI_SEARCH_IOCS_SHARE_LEVEL in param and param[FALCONAPI_SEARCH_IOCS_SHARE_LEVEL] != "all":
            api_data["share_levels"] = param[FALCONAPI_SEARCH_IOCS_SHARE_LEVEL]
        if FALCONAPI_SEARCH_IOCS_FROM_EXPIRATION in param:
            api_data["from.expiration_timestamp"] = param[FALCONAPI_SEARCH_IOCS_FROM_EXPIRATION]
        if FALCONAPI_SEARCH_IOCS_TO_EXPIRATION in param:
            api_data["to.expiration_timestamp"] = param[FALCONAPI_SEARCH_IOCS_TO_EXPIRATION]
        if FALCONAPI_SEARCH_IOCS_SOURCE in param:
            api_data["sources"] = param[FALCONAPI_SEARCH_IOCS_SOURCE]
        if FALCONAPI_SEARCH_IOCS_TYPE in param and param[FALCONAPI_SEARCH_IOCS_TYPE] != "all":
            api_data["types"] = param[FALCONAPI_SEARCH_IOCS_TYPE]
            if param[FALCONAPI_SEARCH_IOCS_TYPE] == "hash":
                api_data["types"] = ["md5", "sha1", "sha256"]

        more = True

        self.send_progress("Completed 0 %")
        data = defaultdict(list)
        ioc_infos = []
        while more:

            ret_val, response = self._call_falcon_api(FALCONAPI_SEARCH_IOCS_APIPATH, action_result, params=api_data)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            ioc_infos.extend(response["resources"])

            offset = response["meta"]["pagination"]["offset"]
            total = response["meta"]["pagination"]["total"]

            if (total):
                self.send_progress(FALCONAPI_COMPLETED, float(len(ioc_infos)) / float(total))

            if offset >= total:
                more = False
            else:
                api_data["offset"] = offset

        self.save_progress("Processing results")

        # instead of adding the ioc type in each ioc_info put them as the value in the dictionary,
        # this way the ioc type 'domain' is not repeated for every domain ioc
        for ioc_info in ioc_infos:

            ioc_type, ioc = (ioc_info.split(':'))
            data[ioc_type].append(ioc)

        summary_keys = ['ip', 'domain', 'sha1', 'md5', 'sha256']

        if (data):

            data = dict(data)
            if ('ipv4' in data):
                data['ip'] = data.pop('ipv4')

            action_result.add_data(data)

            for key in summary_keys:

                if (key not in data):
                    action_result.update_summary({"total_" + key: 0})
                    continue

                action_result.update_summary({"total_" + key: len(data[key])})

        action_result.update_summary({'alerts_found': len(ioc_infos)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_resolve_detection(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        detection_id = param[FALCONAPI_JSON_ID]
        to_state = param[FALCONAPI_RESOLVE_DETECTION_TO_STATE]

        api_data = {
            "ids": detection_id,
            "to_state": to_state
        }

        ret_val, response = self._call_falcon_api(FALCONAPI_RESOLVE_DETECTION_APIPATH, action_result, params=api_data, method="PATCH")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, FALCONAPI_SUCC_GENERAL)

    def _action_list_processes(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[FALCONAPI_JSON_IOC]
        fdid = param[FALCONAPI_GET_PROCESSES_RAN_ON_FALCON_DEVICE_ID]

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        api_data = {
            "type": ioc_type,
            "value": ioc,
            "device_id": fdid
        }

        ret_val, response = self._call_falcon_api(FALCONAPI_GET_PROCESSES_RAN_ON_APIPATH, action_result, params=api_data, fof_ok=True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # successful request / "none found"
        # if len(response["errors"]) == 0 or response["errors"][0]["code"] == 404:
        for p in response["resources"]:
            action_result.add_data({"falcon_process_id": p})
        action_result.set_summary({"process_count": len(response["resources"])})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_list_endpoints(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
                'filter': '',
                'offset': param.get(FALCONAPI_JSON_OFFSET, 0),
                'limit': param.get(FALCONAPI_JSON_LIMIT, 100),
                'sort': 'hostname.asc'}

        filter_query = param.get('filter')
        if (filter_query):
            params['filter'] = filter_query

        ret_val, response = self._call_falcon_api(FALCONAPI_LIST_DEVICES_DETAIL_APIPATH, action_result, params=params, fof_ok=True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        get_details = param.get(FALCONAPI_JSON_GET_DETAILS, True)

        if (not get_details):
            # successful request / "none found"
            for device_id in response["resources"]:
                action_result.add_data({"device_id": device_id})
        else:

            # make the same call with the list of ids to get info about
            params = {'ids': response['resources']}

            ret_val, response = self._call_falcon_api(FALCONAPI_GET_DEVICE_DETAIL_APIPATH, action_result, params=params, fof_ok=True)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            for device in response["resources"]:
                action_result.add_data(device)

        action_result.set_summary({"device_count": action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _action_hunt_file(self, param):

        file_hash = param[phantom.APP_JSON_HASH]

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, ioc_type = self._get_hash_type(file_hash, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._get_devices_ran_on(file_hash, ioc_type, param, action_result)

    def _action_hunt_domain(self, param):

        domain = param[phantom.APP_JSON_DOMAIN]

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._get_devices_ran_on(domain, "domain", param, action_result)

    def _action_test_connectivity(self, param):

        self.save_progress("Attempting to connect to the Falcon Host API")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        action_result = self.add_action_result(ActionResult(dict(param)))

        # query for a single endpoint
        params = {
                'filter': '',
                'offset': 0,
                'limit': 1,
                'sort': 'hostname.asc'}

        ret_val, response = self._call_falcon_api(FALCONAPI_LIST_DEVICES_DETAIL_APIPATH, action_result, params=params, fof_ok=True)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, FALCONAPI_SUCC_CONNECTIVITY_TEST)

    def handle_action(self, param):

        self.debug_print("action_id", self.get_action_identifier())

        # All the action handlers are prefixed with _action_. This is an indication to the author
        # to _not_ change the function definition of that function, else
        # if params are modified, we won't get a compilation error, but a runtime error
        # The safest way to _not_ run into that situation is to use a not so subtle if...else

        return getattr(self, "_action_" + self.get_action_identifier(), phantom.APP_SUCCESS)(param)

if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FalconHostAPI()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ret_val

    exit(0)
