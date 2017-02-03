from datetime import datetime, timedelta
from content.models import DataItem, Item, Group, Role
from person.models import Person
from django.conf import settings
import json
import psycopg2
import os, re
import awsmanager

def delete_expired_data_items():
    now = datetime.now()
    delete_period = timedelta(seconds=settings.DELETE_DATA_ITEM_PERIOD_SECONDS)
    threshold_dt = now - delete_period

    data_items = DataItem.objects.filter(dt_initialization__lt=threshold_dt)
    items = []
    for data_item in data_items:
        items += data_item.items.all()

    groups = []
    for item in items:
        groups += item.groups.all()

    for data_item in data_items:
        success = data_item.delete_data()
        if success:
            data_item.delete()

    for group in set(groups):
        group.maybe_delete()

def make_backup():
    os.popen('su - postgres -c "/usr/bin/pg_dump -h db postgres" > /tmp/backup.bak').read()
    return 'backup created'

def delete_predeleted_roles():
    now = datetime.now()
    roles = Role.objects.filter(expiration_datetime__lte=now, role_type='predeleted')
    for role in roles:
        group = role.group
        role.delete()
        group.maybe_delete()
    return 'completed'


def get_info(mode=''):
    key_exp = re.compile(r'([\w\d]{2}/[\w\d]{2}/)([\w\d]+)')
    s3 = awsmanager.get_connect()
    bucket = s3.get_bucket(settings.AWS_CONF['bucket'])
    all_keys = bucket.get_all_keys()
    all_items = DataItem.objects.all()

    remote_only = []
    remote_only_size = 0
    remote_right = []
    remote_right_size = 0
    remote_total = []
    remote_total_size = 0
    remote_informal = []
    remote_informal_size = 0
    local_only = []
    local_only_size = 0
    local_total = []
    local_total_size = 0

    for key in all_keys:
        remote_total.append({
                'key': key.key,
                'size': key.size
        })
        remote_total_size += key.size
        search_obj = key_exp.search(key.key)
        if search_obj is None:
            remote_informal.append({
                'key': key.key,
                'size': key.size
            })
            remote_informal_size += key.size
        else:
            path = search_obj.groups()[0]
            name = search_obj.groups()[1]
            try:
                data_item = DataItem.objects.get(hash_sum=name)
                remote_right.append({
                    'name': name,
                    'size': key.size
                })
                remote_right_size += key.size
            except DataItem.DoesNotExist:
                remote_only.append({
                    'name': name,
                    'size': key.size
                })
                remote_only_size += key.size

    for item in all_items:
        name = item.hash_sum
        key = '%s/%s/%s' % (name[:2], name[2:4], name)
        local_total.append({
            'name': name,
            'size': item.size_bytes
        })
        local_total_size += item.size_bytes
        try:
            somekey = bucket.get_key(key)
        except:
            local_only.append({
                'name': name,
                'size': item.size_bytes
            })
            local_only_size += item.size_bytes

    return {
        'remote_only': [len(remote_only), remote_only_size],
        'remote_informal': [len(remote_informal), remote_informal_size],
        'remote_right': [len(remote_right), remote_right_size],
        'remote_total': [len(remote_total), remote_total_size],
        'local_total': [len(local_total), local_total_size],
        'local_only': [len(local_only), local_only_size]
    }




