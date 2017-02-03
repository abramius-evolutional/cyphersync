from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from apitools import ApiResponse, GetParams
import tasks

def daily_task(request):
    params, error = GetParams(request, 'GET', ('secret',))
    if error:
        return error
    if params.secret != 'd29d30e48d4a9e4f3df3dkeoocls4yid':
        return ApiResponse({
            'status': 'secret is not right'
        }, 401)
    
    tasks.make_backup()
    tasks.delete_predeleted_roles()
    tasks.delete_expired_data_items()

    return ApiResponse({
        'status': 'daily task has been successfully completed',
    })

def hourly_task(request):
    params, error = GetParams(request, 'GET', ('secret',))
    if error:
        return error
    if params.secret != 'd29d30e48d4a9e4f3df3dkeoocls4yid':
        return ApiResponse({
            'status': 'secret is not right'
        }, 401)

    tasks.delete_predeleted_roles() # to do remove

    return ApiResponse({
        'status': 'hourly task has been successfully completed'
    })

def minutely_task(request):
    params, error = GetParams(request, 'GET', ('secret',))
    if error:
        return error
    if params.secret != 'd29d30e48d4a9e4f3df3dkeoocls4yid':
        return ApiResponse({
            'status': 'secret is not right'
        }, 401)

    tasks.delete_expired_data_items()

    return ApiResponse({
        'status': 'minutely task has been successfully completed'
    })

def info(request):
    params, error = GetParams(request, 'GET', ('secret', 'mode'))
    if error:
        return error
    if params.secret != 'd29d30e48d4a9e4f3df3dkeoocls4yid':
        return ApiResponse({
            'status': 'secret is not right'
        }, 401)

    info = tasks.get_info(params.mode)
    return ApiResponse(info)