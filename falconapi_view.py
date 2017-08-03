# --
# File: falconapi_view.py
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

# import json

import phantom.app as phantom
import phantom.utils as util


def _get_hash_type(hash_value):

    if util.is_md5(hash_value):
        return (phantom.APP_SUCCESS, "md5")

    if util.is_sha1(hash_value):
        return (phantom.APP_SUCCESS, "sha1")

    if util.is_sha256(hash_value):
        return (phantom.APP_SUCCESS, "sha256")

    return (phantom.APP_ERROR, None)


def _get_ioc_type(ioc):

    if util.is_ip(ioc):
        return (phantom.APP_SUCCESS, "ip")

    if util.is_hash(ioc):
        return _get_hash_type(ioc)

    if util.is_domain(ioc):
        return (phantom.APP_SUCCESS, "domain")

    return (phantom.APP_ERROR, "Failed to detect the IOC type")


def _trim_results(data, key):

    if (key not in data):
        return

    if (len(data[key]) <= 100):
        return

    data[key] = data[key][:101]

    data[key][-1] = '...'


def get_ctx_result_hunt(result):

    ctx_result = {}

    param = result.get_param()

    hunt_object = param.get('hash')
    if (not hunt_object):
        hunt_object = param.get('domain')

    param['ioc'] = hunt_object
    ret_val, param['ioc_type'] = _get_ioc_type(hunt_object)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def get_ctx_result_ps(result):

    ctx_result = {}

    param = result.get_param()

    if ('ioc' in param):
        ioc = param.get('ioc')
        ret_val, param['ioc_type'] = _get_ioc_type(ioc)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def get_ctx_result(result):

    ctx_result = {}

    param = result.get_param()

    if ('ioc' in param):
        ioc = param.get('ioc')
        ret_val, param['ioc_type'] = _get_ioc_type(ioc)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]

    if (not data):
        return ctx_result

    _trim_results(data, 'ip')
    _trim_results(data, 'domain')
    _trim_results(data, 'sha256')
    _trim_results(data, 'sha1')
    _trim_results(data, 'md5')

    ctx_result['data'] = data

    return ctx_result


def create_alert_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'create_alert_view.html'


def get_alert_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'get_alert_view.html'


def update_alert_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'update_alert_view.html'


def set_status_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'set_status_view.html'


def list_alerts_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'list_alerts_view.html'


def process_list_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result_ps(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'process_list_view.html'


def hunt_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result_hunt(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'hunt_view.html'
