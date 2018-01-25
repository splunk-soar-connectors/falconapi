# --
# File: FalconAPI_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

FALCONAPI_BASE_URL = "baseurl"
FALCONAPI_USER = "user"
FALCONAPI_KEY = "key"

FALCONAPI_GET_DEVICE_COUNT_APIPATH = "/indicators/aggregates/devices-count/v1"
FALCONAPI_GET_DEVICES_RAN_ON_APIPATH = "/indicators/queries/devices/v1"
FALCONAPI_GET_PROCESSES_RAN_ON_APIPATH = "/indicators/queries/processes/v1"
FALCONAPI_GET_PROCESS_DETAIL_APIPATH = "/processes/entities/processes/v1"
FALCONAPI_GET_DEVICE_DETAIL_APIPATH = "/devices/entities/devices/v1"
FALCONAPI_UPLOAD_IOCS_APIPATH = "/indicators/entities/iocs/v1"
FALCONAPI_GET_IOCS_APIPATH = "/indicators/entities/iocs/v1"
FALCONAPI_UPDATE_IOCS_APIPATH = "/indicators/entities/iocs/v1"
FALCONAPI_DELETE_IOCS_APIPATH = "/indicators/entities/iocs/v1"
FALCONAPI_SEARCH_IOCS_APIPATH = "/indicators/queries/iocs/v1"
FALCONAPI_RESOLVE_DETECTION_APIPATH = "/detects/entities/detects/v1"
FALCONAPI_TEST_PATH = FALCONAPI_GET_DEVICE_COUNT_APIPATH
FALCONAPI_LIST_DEVICES_DETAIL_APIPATH = "/devices/queries/devices/v1"

FALCONAPI_JSON_IOC = "ioc"

FALCONAPI_GET_PROCESSES_RAN_ON_FALCON_DEVICE_ID = "id"
FALCONAPI_GET_PROCESS_DETAIL_FALCON_PROCESS_ID = "falcon_process_id"
FALCONAPI_GET_DEVICE_DETAIL_FALCON_DEVICE_ID = "id"
FALCONAPI_UPLOAD_IOCS_POLICY = "policy"
FALCONAPI_UPLOAD_IOCS_SHARE_LEVEL = "share_level"
FALCONAPI_UPLOAD_IOCS_EXPIRATION = "expiration"
FALCONAPI_UPLOAD_IOCS_SOURCE = "source"
FALCONAPI_UPLOAD_IOCS_DESCRIPTION = "description"
FALCONAPI_GET_IOCS_IOC_ID = "ioc_id"
FALCONAPI_UPDATE_IOCS_IOC_ID = "ioc_id"
FALCONAPI_UPDATE_IOCS_POLICY = "policy"
FALCONAPI_UPDATE_IOCS_SHARE_LEVEL = "share_level"
FALCONAPI_UPDATE_IOCS_EXPIRATION = "expiration"
FALCONAPI_UPDATE_IOCS_SOURCE = "source"
FALCONAPI_UPDATE_IOCS_DESCRIPTION = "description"
FALCONAPI_DELETE_IOCS_IOC_ID = "ioc_id"
FALCONAPI_SEARCH_IOCS_TYPE = "type"
FALCONAPI_SEARCH_IOCS_POLICY = "policy"
FALCONAPI_SEARCH_IOCS_SHARE_LEVEL = "share_level"
FALCONAPI_SEARCH_IOCS_FROM_EXPIRATION = "from_expiration"
FALCONAPI_SEARCH_IOCS_TO_EXPIRATION = "to_expiration"
FALCONAPI_SEARCH_IOCS_SOURCE = "source"
FALCONAPI_RESOLVE_DETECTION_DETECTION = "detection"
FALCONAPI_RESOLVE_DETECTION_TO_STATE = "state"
FALCONAPI_JSON_COUNT_ONLY = "count_only"
FALCONAPI_JSON_OFFSET = "offset"
FALCONAPI_JSON_LIMIT = "limit"
FALCONAPI_JSON_GET_DETAILS = "get_details"
FALCONAPI_JSON_ID = "id"

FALCONAPI_ERR_INVALID_URL = "Invalid Falcon API URL"
FALCONAPI_ERR_INVALID_RESPONSE = "Invalid data returned from API"
FALCONAPI_ERR_INVALID_CREDENTIALS = "Invalid user or key"
FALCONAPI_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
FALCONAPI_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
FALCONAPI_ERR_UNSUPPORTED_HASH_TYPE = "Unsupported hash type"
FALCONAPI_ERR_GENERAL = "Falcon Host API call failed"
FALCONAPI_SUCC_GENERAL = "Falcon Host API call successful"
FALCONAPI_ERR_API_UNSUPPORTED_METHOD = "Unsupported method"
FALCONAPI_ERR_SERVER_CONNECTION = "Connection failed"
FALCONAPI_ERR_JSON_PARSE = "Unable to parse reply as a Json, raw string reply: '{raw_text}'"
FALCONAPI_ERR_FROM_SERVER = "API failed, Status code: {status}, Detail: {detail}"
FALCONAPI_ERR_MESSAGES_FROM_SERVER = "API failed, Details: {0}"
FALCONAPI_COMPLETED = "Completed {0:.0%}"
