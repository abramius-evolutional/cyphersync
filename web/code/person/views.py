from apitools import ApiResponse, GetParams
from serializers import PersonSerializer, DeviceSerializer
import person
import tokenauth.models

def person_about(request):
    params, error = GetParams(request, 'GET', ('accessToken',))
    
    token = tokenauth.models.AccessToken.getAccessToken(params.accessToken)
    if (token is None):
        return ApiResponse({
            'status': 'token is not found'
        }, 404)
    if (token.user is None):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)
    if (token.user.is_active==False):
        return ApiResponse({
            'status': 'user is not active'
        }, 404)

    serializer = PersonSerializer(token.user)
    return ApiResponse(serializer.data)

def device_about(request):
    params, error = GetParams(request, 'GET', ('accessToken',))
    
    token = tokenauth.models.AccessToken.getAccessToken(params.accessToken)
    if (token is None):
        return ApiResponse({
            'status': 'token is not found'
        }, 404)
    if (token.user is None):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)
    if (token.user.is_active==False):
        return ApiResponse({
            'status': 'user is not active'
        }, 404)

    serializer = DeviceSerializer(token.device)
    return ApiResponse(serializer.data)

def person_devices(request):
    params, error = GetParams(request, 'GET', ('accessToken',))
    
    token = tokenauth.models.AccessToken.getAccessToken(params.accessToken)
    if (token is None):
        return ApiResponse({
            'status': 'token is not found'
        }, 404)
    if (token.user is None):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)
    if (token.user.is_active==False):
        return ApiResponse({
            'status': 'user is not active'
        }, 404)

    serializer = DeviceSerializer(token.user.devices.all(), many=True)
    return ApiResponse(serializer.data)
