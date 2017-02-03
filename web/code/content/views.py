from django.shortcuts import render
from apitools import ApiResponse, GetParams
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
from django.utils.timezone import utc
from django.conf import settings
from person.models import Device, Person
import hashlib
import tokenauth
import serializers
import models
import json

def _request_add_file(request):
    params, error = GetParams(request, 'GET', ('accessToken', 
        'group_ids',
        'size_bytes'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)

    admin_roles = user.roles.filter(role_type='administrator')
    total_size_bytes = 0
    for admin_role in admin_roles:
        items = admin_role.group.items.all()
        for item in items:
            total_size_bytes += item.data.size_bytes

    if (total_size_bytes + int(params.size_bytes) > settings.USER_FREE_VOLUME_BYTES):
        return ApiResponse({
            'status': 'memory error'
        }, 403)

    result = []

    target_groups = []
    log = 'warnings:\n'

    group_ids = json.loads(params.group_ids)
    keys = []
    result_devices = {}
    for group_id in group_ids:
        try:
            group = models.Group.objects.get(id=group_id)
            group_keys, err = group.get_all_needed_pubkeys(user)
        except models.Group.DoesNotExist:
            group_keys, err = None, 'group with group_id=%i is not found' % group_id

        if err is not None:
            log += err + '\n'
        if group_keys is not None:
            keys += group_keys

    result_devices = {}
    for k in keys:
        result_devices[k['device_id']] = {
            'pub_key': k['pub_key'],
            'email': k['email'],
            'device_name': k['device_name'],
            'device_id': k['device_id']
        }

    return ApiResponse({
        'keys': result_devices.values(),
        'error_log': log,
    })

def _add_file(request):

    params, error = GetParams(request, 'POST', ('accessToken', 
        'group_ids',
        'metadata',
        'cyphers',))
    if error:
        return error

    aws_data = request.POST.get('aws_data')
    item_id = request.POST.get('item_id')
    if (aws_data is None) & (item_id is None):
        return ApiResponse({
            'status': 'aws_data or item_id is not found'
        }, 404)

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)

    target_groups = []

    group_ids = json.loads(params.group_ids)
    for group_id in group_ids:
        try:
            group = models.Group.objects.get(id=group_id)
        except models.Group.DoesNotExist:
            continue

        roles = group.roles.filter(person=user)
        if len(roles)==0:
            continue
        
        role = roles[0]
        if role.access_add_file():
            target_groups.append(group)

    if len(target_groups)==0:
        return ApiResponse({
            'status': 'not found any groups'
        }, 404)

    meta_hash = hashlib.sha256(params.metadata).hexdigest()

    now = datetime.now().replace(tzinfo=utc)

    if (item_id is not None):
        try:
            item = models.Item.objects.get(id=item_id)
        except models.Item.DoesNotExist:
            return ApiResponse({
                'status': 'item is not found'
            }, 404)
        if len(item.data.accesses.filter(device__owner=user)) == 0:
            return ApiResponse({
                'status': 'you do not have access for this item'
            }, 404)
        dataItem = item.data
    else:
        try:
            aws = json.loads(aws_data)
            aws['url']
            aws['bucket']
            aws['key']
            aws['hash_data']
            int(aws['size_bytes'])
        except:
            return ApiResponse({
                'status': 'encorrect aws_data'
            }, 400)
        size_bytes = int(aws['size_bytes'])
        dataItem = models.DataItem.get_or_create(aws)

        item = models.Item.objects.create(data=dataItem, 
            meta_hash_sum=meta_hash,
            details=params.metadata,
            version=1,
            dt_modification=now,
            dt_initialization=now)
        item.save()

    for group in target_groups:
        group.items.add(item)
        group.save()

    try:
        cyphers = json.loads(params.cyphers)
    except:
        return ApiResponse({
            'status': 'cyphers is not a json string'
        }, 500)

    for device_id in cyphers:
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            continue
        cypher = cyphers[device_id]
        new_access = models.Access.create_or_update(creator=user,
            data_item=dataItem,
            device=device,
            cypher_key=cypher)

    item_serializer = serializers.ItemSerializer(item)

    return ApiResponse({
        'status': 'saved',
        'item': item_serializer.data
    })

@csrf_exempt
def add_file(request):
    if request.method=='POST':
        return _add_file(request)
    elif request.method=='GET':
        return _request_add_file(request)
    else:
        return ApiResponse({
            'status': 'HTTP method must be GET or POST'
        }, 403)

def delete_file(request):
    params, error = GetParams(request, 'GET', ('accessToken', 
        'item_id',
        'group_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)

    does_have_access = False
    group = None
    for role in user.roles.filter(group__id=params.group_id):
        if (role.access_remove_file() == True):
            does_have_access = True
            group = role.group

    if (does_have_access == False):
        return ApiResponse({
            'status': 'you do not have needed access for this group'
        }, 404)

    try:
        item = group.items.get(id=params.item_id)
    except models.Item.DoesNotExist:
        return ApiResponse({
            'status': 'file is not found'
        }, 404)

    if len(item.data.accesses.filter(device__owner=user)) == 0:
        return ApiResponse({
            'status': 'you do not have access for this file'
        }, 404)

    group.items.remove(item)
    group.save()
    item.maybe_delete()
    # data_item = item.data
    # data_item.maybe_delete()

    return ApiResponse({
        'status': 'item has been deleted from group'
    })

def change_item(request, user, item):
    params, error = GetParams(request, 'POST', ('metadata',
        'prev_hash_meta'))
    if error:
        return error

    status = ''
    response_item = item

    new_item = None
    meta_hash_sum = hashlib.sha256(params.metadata).hexdigest()
    if params.prev_hash_meta == item.meta_hash_sum:
        if meta_hash_sum != item.meta_hash_sum:
            item.meta_hash_sum = meta_hash_sum
            item.details = params.metadata
            item.version += 1
            item.dt_modification = datetime.now().replace(tzinfo=utc)
            item.save()
            status += '(meta: updated) '
        else:
            status += '(meta: nothing to update) '
    elif (params.prev_hash_meta == meta_hash_sum):
        status += '(meta: meta is equals)'
    else:
        new_item = models.Item.objects.create(data=item.data,
            meta_hash_sum=meta_hash_sum,
            details=params.metadata,
            version=1,
            dt_modification=datetime.now().replace(tzinfo=utc),
            dt_initialization=datetime.now().replace(tzinfo=utc))
        new_item.save()
        status += '(meta: new item with meta) '

    new_data_item = None

    aws_data = request.POST.get('aws_data')
    if aws_data is not None:
        try:
            aws = json.loads(aws_data)
            aws['url']
            aws['bucket']
            aws['key']
            aws['hash_data']
        except:
            return ApiResponse({
                'status': 'encorrect aws_data'
            }, 400)
        prev_hash_data = request.POST.get('prev_hash_data')
        if prev_hash_data is None:
            return ApiResponse({
                'status': 'parameter rev_hash_data is not found'
            }, 401)
        if prev_hash_data == item.data.hash_sum:
            data_hash_sum = aws['hash_data']
            if item.data.hash_sum != data_hash_sum:
                old_data_item = item.data
                data_item = models.DataItem.get_or_create(aws)
                if data_item != old_data_item:
                    accesses = old_data_item.accesses.all()
                    for access in accesses:
                        access.item = data_item
                        access.save()
                item.data = data_item
                item.save()
                old_data_item.maybe_delete()
                status += '(data: update data) '
        else:
            new_data_item = models.DataItem.get_or_create(aws)
            status += '(data: new item with data) '

    if (new_data_item is not None) | (new_item is not None):
        if new_data_item is None:
            new_data_item = item.data
        if new_item is None:
            new_item = item
        old_data_item = new_item.data
        new_item.data = new_data_item
        new_item.save()
        old_data_item.maybe_delete()
        response_item = new_item
        for group in item.groups.all():
            roles_for_user = group.roles.filter(person=user)
            roles_for_user = filter(lambda r: r.access_add_file(), roles_for_user)
            if len(roles_for_user) > 0:
                group.items.add(new_item)
                group.save()
    
    item_serializer = serializers.ItemSerializer(response_item)
    return ApiResponse({
        'status': status,
        'item': item_serializer.data
    })


@csrf_exempt
def change_file(request):
    params, error = GetParams(request, 'POST', ('accessToken', 
        'item_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)

    try:
        item = models.Item.objects.get(id=params.item_id)
    except models.Item.DoesNotExist:
        return ApiResponse({
            'status': 'item is not found'
        }, 404)

    is_role = False
    for group in item.groups.all():
        roles = group.roles.filter(person=user)
        roles = filter(lambda r: r.access_add_file(), roles)
        if len(roles) > 0:
            is_role = True

    if not is_role:
        return ApiResponse({
            'status': 'you con not change this file'
        }, 404)

    accesses = item.data.accesses.filter(device__owner=user)
    if len(accesses)==0:
        return ApiResponse({
            'status': 'you do not have an access for this item'
        }, 404)

    return change_item(request, user, item)

    return ApiResponse({}, 500)



def get_files(request):
    params, error = GetParams(request, 'GET', ('accessToken',))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)

    roles = user.roles.all()
    read_access_roles = filter(lambda r: (r.access_read_file()==True)&(r.is_confirmed==True), roles)
    items = {}
    details = {}
    for role in read_access_roles:
        for item in role.group.items.all():
            curr_details = details.get(item.id, {
                'groups': []
            })
            curr_details['groups'].append({
                'role_type': role.role_type,
                'id': role.group.id,
                'name': role.group.name,
                'is_private': role.group.is_private
            })
            details[item.id] = curr_details
            items[item.id] = item

    items = items.values()
    details = details.values()

    accessToken = tokenauth.models.AccessToken.objects.get(token=params.accessToken)
    device = accessToken.device

    for i in range(len(items)):
        item = items[i]
        d = details[i]
        setattr(item, 'group_details', d)
        accesses = item.data.accesses.filter(device=device)
        if len(accesses) > 0:
            setattr(item, 'cypher_key', accesses[0].cypher_key)
        else:
            setattr(item, 'cypher_key', '')

    return ApiResponse({
        'items': serializers.ItemSerializer(items, many=True).data
    })

@csrf_exempt
def add_role(request):

    if request.method=='GET':
        params, error = GetParams(request, 'GET', ('accessToken', 'group_id', 'target_email'))
        if error:
            return error

    elif request.method=='POST':
        params, error = GetParams(request, 'POST', ('accessToken',
            'group_id', 
            'target_email',
            'role_type',
            'cyphers'))
        if error:
            return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'permission denied'
        }, 404)
    if user.email==params.target_email:
        return ApiResponse({
            'status': 'you con not add role for yourself'
        }, 404)

    target_user = None
    try:
        target_user = Person.objects.get(email=params.target_email)
    except Person.DoesNotExist:
        return ApiResponse({
            'status': 'target user \'%s\' is not found' % params.target_email
        }, 404)

    try:
        group = models.Group.objects.get(id=params.group_id)
    except models.Group.DoesNotExist:
        return ApiResponse({
            'status': 'group is not found'
        }, 404)

    admin_roles = user.roles.filter(role_type='administrator')
    current_roles = filter(lambda r: r.group==group, admin_roles)
    if len(current_roles)==0:
        return ApiResponse({
            'status': 'you have not a role for this group'
        }, 404)

    role = current_roles[0]

    accessToken = tokenauth.models.AccessToken.objects.get(token=params.accessToken)
    device = accessToken.device
    target_devices = target_user.devices.all()

    if request.method=='GET':
        file_keys_with_my_pubkey = group.get_needed_accesses_for_person(device)
        return ApiResponse({
            'my_pub_key': device.pub_key,
            'file_keys': file_keys_with_my_pubkey,
            'target_devices': map(lambda d: {
                'device_id': d.id,
                'pub_key': d.pub_key
            }, target_devices)
        })
    elif request.method=='POST':
        cyphers = json.loads(params.cyphers)
        new_role = models.Role.create_or_update(creator=user,
            person=target_user,
            dt_initialization=datetime.now().replace(tzinfo=utc),
            group=group,
            role_type=params.role_type)
        count = 0

        for l in cyphers:
            item_id = l['data_item_id']
            try:
                data_item = models.DataItem.objects.get(id=item_id)
            except models.DataItem.DoesNotExist:
                continue
            device_id = l['device_id']
            try:
                device = Device.objects.get(id=device_id)
            except Device.DoesNotExist:
                continue
            secret_key = l['secret_key']
            
            new_access = models.Access.create_or_update(creator=user,
                data_item=data_item,
                device=device,
                cypher_key=secret_key)
            count += 1
        return ApiResponse({
            'status': 'added %i accesses' % count
        })

    return ApiResponse({
        'status': 'HTTP method must be GET or POST'
    }, 403)

def confirm_role(request):
    params, error = GetParams(request, 'GET', ('accessToken', 'role_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    try: 
        role = models.Role.objects.get(id=params.role_id)
    except models.Role.DoesNotExist:
        return ApiResponse({
            'status': 'role is not found'
        }, 404)

    role.is_confirmed = True
    role.save()
    return ApiResponse({
        'status': 'confirmed'
    })

def delete_role(request):
    params, error = GetParams(request, 'GET', ('accessToken', 'role_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    try: 
        role = models.Role.objects.get(id=params.role_id)
    except models.Role.DoesNotExist:
        return ApiResponse({
            'status': 'role is not found'
        }, 404)

    if (user != role.creator) & (user != role.person):
        return ApiResponse({
            'status': 'you can not delete this role'
        }, 404)

    group = role.group

    if group.is_private:
        return ApiResponse({
            'status': 'you con not delete private group|s role'
        }, 404)

    if (user == role.creator) & (user != role.person) & (role.role_type=='administrator'):
        td = timedelta(hours=settings.PREDELETED_ROLE_PERIOD_HOURS)
        role.role_type = 'predeleted'
        role.expiration_datetime = datetime.now() + td
        role.save()
    else:
        role.delete()
        group.maybe_delete()

    return ApiResponse({
        'status': 'role has been deleted'
    })


@csrf_exempt
def create_group(request):

    params, error = GetParams(request, 'POST', ('accessToken', 'name'))
    if error:
        return error

    group_type = request.POST.get('group_type', '')

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    new_group = models.Group.objects.create(creator=user,
        dt_initialization=datetime.now().replace(tzinfo=utc),
        name=params.name,
        is_private=False,
        group_type=group_type)
    new_group.save()

    new_role = models.Role.objects.create(creator=user,
        dt_initialization=datetime.now().replace(tzinfo=utc),
        person=user,
        group=new_group,
        role_type='administrator',
        is_confirmed=True)
    new_role.save()

    role_serializer = serializers.RoleSerializer(new_role)

    return ApiResponse({
        'role': role_serializer.data
    }, 200)

def get_roles(request):
    
    params, error = GetParams(request, 'GET', ('accessToken',))
    if error:
        return error
    
    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    roles = user.roles.all()
    roles_serializer = serializers.RoleSerializer(roles, many=True)

    return ApiResponse({
        'my_user_id': user.id,
        'roles': roles_serializer.data
    });

def delete_group(request):

    params, error = GetParams(request, 'GET', ('accessToken', 'group_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    try:
        group = user.groups_created_by_me.get(id=params.group_id)
    except models.Group.DoesNotExist:
        return ApiResponse({
            'status': 'you did not create this group'
        }, 404)

    if group.is_private:
        return ApiResponse({
            'status': 'you can not delete your private group'
        })

    items = group.items.all()
    for item in items:
        group.items.remove(item)
    group.save()
    group.delete()

    for item in items:
        # item.data.maybe_delete()
        item.maybe_delete()

    return ApiResponse({
        'status': 'group has been deleted'
    })

def check_accesses(request):
    params, error = GetParams(request, 'GET', ('accessToken',))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    accessToken = tokenauth.models.AccessToken.objects.get(token=params.accessToken)
    device = accessToken.device

    admin_roles = filter(lambda r: (r.access_add_file() == True), user.roles.all())
    admin_groups = map(lambda r: r.group, admin_roles)

    missings = []
    for group in admin_groups:
        m, err = group.missing_cypher_accesses(device)
        if err is None:
            missings += m

    return ApiResponse({
        'missing_cypher_accesses': m
    })

@csrf_exempt
def add_cypher_access(request):
    params, error = GetParams(request, 'POST', ('accessToken',
        'cypher_key',
        'device_id',
        'data_item_id'))
    if error:
        return error

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    try:
        data_item = models.DataItem.objects.get(id=params.data_item_id)
    except:
        return ApiResponse({
            'status': 'data item is not found'
        }, 404)

    try:
        my_access = data_item.accesses.get(device__owner=user)
    except:
        return ApiResponse({
            'status': 'you do not have access for this data item'
        }, 404)

    try:
        device = Device.objects.get(id=params.device_id)
    except:
        return ApiResponse({
            'status': 'device is not found'
        }, 404)

    new_access = models.Access.create_or_update(creator=user,
                data_item=data_item,
                device=device,
                cypher_key=params.cypher_key)

    new_access.save()

    return ApiResponse({
        'status': 'saved'
    })

def actual_aws_info(request):
    params, error = GetParams(request, 'GET', ('accessToken', 'hash_data'))
    if error:
        return error

    if len(params.hash_data) < 4:
        return ApiResponse({
            'status': 'encorrect hash_data'
        }, 400)

    user = tokenauth.models.AccessToken.access(params.accessToken)
    if (user is None) or (user.is_active==False):
        return ApiResponse({
            'status': 'user is not found'
        }, 404)

    return ApiResponse({
        'aws_bucket': settings.AWS_CONF['bucket'],
        'aws_dir': '%s/%s/' % (params.hash_data[:2], params.hash_data[2:4])
    })
