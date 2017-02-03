from django.shortcuts import render
from apitools import ApiResponse, GetParams
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
from django.utils.timezone import utc
from django.conf import settings
from django.core.files.base import ContentFile
import hashlib
import uuid
import json

import models
import person
import content


def md5(string):
    m = hashlib.md5()
    m.update(string)
    return m.hexdigest()

def permission(email, password, secret):
    return md5(email + 'fuck you' + password) == secret

@csrf_exempt
def registration(request):
    if request.method!='POST':
        return ApiResponse({
            'status': 'HTTP method must be POST'
        }, 405)

    params, error = GetParams(request, 'POST', ('email', 
        'password', 
        'secret',
        'name'))
    if error:
        return error

    if permission(params.email, params.password, params.secret)!=True:
        return ApiResponse({
            'status': 'permission denied'
        }, 401)

    try:
        user_with_email = person.models.Person.objects.get(email=params.email, is_active=True)
    except person.models.Person.DoesNotExist:
        user_with_email = None

    try:
        user_with_name = person.models.Person.objects.get(name=params.name, is_active=True)
    except person.models.Person.DoesNotExist:
        user_with_name = None

    if (user_with_email is not None):
        return ApiResponse({
            'status': 'email already exist'
        }, 404)

    if (user_with_name is not None):
        return ApiResponse({
            'status': 'name already exist'
        }, 404)

    user = person.models.Person.objects.create(email=params.email, 
        password=params.password,
        creation_datetime=datetime.now(),
        name=params.name,
        details=request.POST.get('details', '{}'))
    user.save()

    f = request.FILES.get('avatar', None)
    if f is not None:
        file_content = ContentFile(f.read())
        user.avatar.save(f.name, file_content)
    

    group = content.models.Group.objects.create(creator=user,
        dt_initialization=datetime.now().replace(tzinfo=utc),
        name='Private group',
        is_private=True)
    group.save()

    role = content.models.Role.objects.create(creator=user,
        dt_initialization=datetime.now().replace(tzinfo=utc),
        person=user,
        group=group,
        role_type='administrator',
        is_confirmed=True)

    dt = datetime.now().replace(tzinfo=utc) + timedelta(days=7)
    confirmationToken = models.ConfirmationToken.objects.create(token=str(uuid.uuid4()),
        dt_expiration=dt, 
        user=user)
    confirmationToken.save()
    # confirmationToken.sendmail()

    return ApiResponse({
        'status': 'user has been created'
    }, 200)

@csrf_exempt
def change(request):
    params, error = GetParams(request, 'POST', ('accessToken',))
    
    user = models.AccessToken.access(params.accessToken)
    if (user is None):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)
    if (user.is_active==False):
        return ApiResponse({
            'status': 'user is not active'
        }, 404)

    new_name = request.POST.get('name', None)
    if new_name is not None:
        user.name = new_name

    new_avatar = request.FILES.get('avatar', None)
    if new_avatar is not None:
        file_content = ContentFile(new_avatar.read())
        user.avatar.save(new_avatar.name, file_content)

    new_details = request.POST.get('details', None)
    if new_details is not None:
        user.details = new_details

    user.save()

    return ApiResponse({
        'status': 'updated'
    })

def details(request):
    if request.method!='GET':
        return ApiResponse({
            'status': 'HTTP method must be GET'
        }, 405)

    params, error = GetParams(request, 'GET', ('email', 
                                                'password', 
                                                'secret'))
    if error:
        return error

    if permission(params.email, params.password, params.secret)!=True:
        return ApiResponse({
            'status': 'permission denied'
        }, 401)

    try:
        user = person.models.Person.objects.get(email=params.email, is_active=True)
    except person.models.Person.DoesNotExist:
        user = None

    if user is None:
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    if user.password != params.password:
        return ApiResponse({
            'status': 'user is not found'
        }, 404) 

    return ApiResponse({
        'details': user.details
    }, 200)

    
def login(request):
    if request.method!='GET':
        return ApiResponse({
            'status': 'HTTP method must be GET'
        }, 405)

    params, error = GetParams(request, 'GET', ('email', 
                                                'password', 
                                                'secret', 
                                                'device_id', 
                                                'pub_key', 
                                                'device_name'))
    if error:
        return error

    if permission(params.email, params.password, params.secret)!=True:
        return ApiResponse({
            'status': 'permission denied'
        }, 401)

    try:
        user = person.models.Person.objects.get(email=params.email, is_active=True)
    except person.models.Person.DoesNotExist:
        user = None

    if user is None:
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    if user.password != params.password:
        return ApiResponse({
            'status': 'user is not found'
        }, 404) 

    try:
        device = person.models.Device.objects.get(pub_key=params.pub_key)
        device.owner = user
        device.name = params.device_name
        device.save()
    except person.models.Device.DoesNotExist:
        device = person.models.Device.objects.create(owner=user,
            device_id=params.device_id,
            pub_key=params.pub_key,
            name=params.device_name)

    user.devices.add(device)
    user.devices.add(device)

    new_token = str(uuid.uuid4())
    try:
        accessToken = models.AccessToken.objects.get(token=new_token)
    except models.AccessToken.DoesNotExist:
        accessToken = None
    while (accessToken is not None):
        new_token = str(uuid.uuid4())
        try:
            accessToken = models.AccessToken.objects.get(token=new_token)
        except models.AccessToken.DoesNotExist:
            accessToken = None

    accessToken = models.AccessToken.objects.create(token=new_token,
            dt_initialization=datetime.now().replace(tzinfo=utc),
            dt_expiration=datetime.now().replace(tzinfo=utc) + timedelta(days=30),
            device=device,
            user=user)
    accessToken.details = json.dumps({
        'pub_key': params.pub_key
    })
    accessToken.save()

    return ApiResponse({
        'accessToken': accessToken.token
    }, 200)
    
def confirm(request, token):
    if request.method!='GET':
        return ApiResponse({
            'status': 'HTTP method must be GET'
        }, 405)

    try:
        confirmation_token = models.ConfirmationToken.objects.get(token=token, 
            dt_expiration__gte=datetime.now())
    except models.ConfirmationToken.DoesNotExist:
        confirmation_token = None

    if confirmation_token is None:
        return ApiResponse({
            'status': 'it has not found'
        }, 404)

    user = confirmation_token.user
    user.is_confirmed = True
    user.save()

    user.confirmation_tockens.all().update(dt_expiration=datetime.now())

    return ApiResponse({
        'status': 'user has been confirmed'
    }, 200)
    
def logout(request):
    if request.method!='GET':
        return ApiResponse({
            'status': 'HTTP method must be GET'
        }, 405)

    token = request.GET.get('accessToken')
    email = request.GET.get('email')
    password = request.GET.get('password')
    secret = request.GET.get('secret')
    device_id = request.GET.get('device_id')

    user = None
    device = None

    if (token is not None):
        accessToken = models.AccessToken.getAccessToken(token)
        if accessToken is None:
            return ApiResponse({
                'status': 'token is not found'
            }, 404)
        user = accessToken.user
        device = accessToken.device
    elif (email is not None) & (password is not None) & (secret is not None):
        if permission(email, password, secret)==False:
            return ApiResponse({
                'status': 'permission denied'
            }, 401)
        try:
            user = person.models.Person.objects.get(email=email, password=password)
        except:
            user = None

    if device is not None:
        device.access_tokens.filter(user=user).update(dt_expiration=datetime.now())
        return ApiResponse({
            'status': 'success for one device'
        }, 200)
    
    if user is not None:
        user.access_tokens.all().update(dt_expiration=datetime.now())
        return ApiResponse({
            'status': 'success for all devices'
        }, 200)

    return ApiResponse({
        'status': 'error'
    }, 404)


def change_password_request(request):
    if request.method!='GET':
        return ApiResponse({
            'status': 'HTTP method must be GET'
        }, 405)

    email = request.GET.get('email')
    if email is None:
        return ApiResponse({
            'status': 'error input parameters'
        }, 401)
    try:
        user = person.models.Person.objects.get(email=email, is_active=True)
    except person.Person.objects.DoesNotExist:
        user = None

    if user is None:
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    dt = datetime.now().replace(tzinfo=utc) + timedelta(days=1)
    passwordToken = models.ChangePasswordToken.objects.create(dt_expiration=dt, user=user)
    passwordToken.save()
    passwordToken.sendmail()

    return ApiResponse({
        'status': 'message has been sent'
    })

@csrf_exempt
def change_password(request, token):

    try:
        passwordToken = models.ChangePasswordToken.objects.get(token=token, 
            dt_expiration__gte=datetime.now())
    except:
        passwordToken = None

    if passwordToken is None:
        return ApiResponse({
            'status': 'bed request'
        })

    if request.method=='GET':

        return render(request, 'change_password.html', {
            'token': token,
            'email': passwordToken.user.email
        })

    elif request.method=='POST':

        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if (password1 is None) | (password1 != password2):
            return ApiResponse({
                'status': 'passwords are not equals'
            }, 403)

        user = passwordToken.user
        user.password = password1
        user.save()

        user.change_password_tokens.all().update(dt_expiration=datetime.now())

        return ApiResponse({
            'status': 'password has been changed'
        })
    else:
        return ApiResponse({
            'status': 'HTTP method must be GET or POST'
        }, 400)

@csrf_exempt
def set_push_id(request):
    params, error = GetParams(request, 'POST', ('access_token', 
        'vendor', 
        'push_identifier'))
    if error: return error

    accessToken = models.AccessToken.getAccessToken(token=params.access_token)
    if accessToken is None:
        return ApiResponse({
            'status': 'AccessToken is not found'
        }, 404)
    device = accessToken.device
    device.vendor = params.vendor
    device.push_identifier = params.push_identifier
    device.save()

    return ApiResponse({
        'status': 'saved'
    })

def __delete_person(request):
    if settings.DEBUG:
        email = request.GET.get('email')

        try:
            user = person.models.Person.objects.get(email=email)
            user.delete()
        except:
            pass

        return ApiResponse({}, 200)


    return ApiResponse({}, 401)
