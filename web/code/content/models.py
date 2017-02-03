from django.db import models
from datetime import datetime
from django.utils.timezone import utc
from django.conf import settings
from person.models import Device
from awsmanager import AWSManager

import hashlib
import uuid
import os
import json

class DataItem(models.Model):
    hash_sum = models.TextField(null=True, unique=True)
    aws_info = models.TextField(null=True)
    dt_initialization = models.DateTimeField()
    version = models.IntegerField()
    internal_details = models.TextField(default='', blank=True)
    size_bytes = models.BigIntegerField()
    def __unicode__(self):
        return str(self.id)
    def delete_data(self):
        aws = json.loads(self.aws_info)
        s3 = AWSManager()
        aws_bucket = aws['bucket']
        aws_key = aws['key']
        return s3.delete_key(aws_bucket, aws_key)
    def maybe_delete(self):
        items = self.items.all()
        group_count = 0
        for item in items:
            group_count += len(item.groups.all())
        if (group_count == 0):
            if self.delete_data():
                self.delete()
                return True
        return False
    @classmethod
    def get_or_create(cls, aws):
        hash_sum = aws['hash_data']
        size_bytes = aws['size_bytes']
        now = datetime.now().replace(tzinfo=utc)
        try:
            dataItem = cls.objects.get(hash_sum=hash_sum)
            dataItem.dt_initialization = now
        except cls.DoesNotExist:
            dataItem = cls.objects.create(hash_sum=hash_sum,
                aws_info=json.dumps(aws),
                dt_initialization=now,
                version=1,
                size_bytes=int(size_bytes))
        dataItem.save()
        return dataItem

class Item(models.Model):
    data = models.ForeignKey('DataItem', related_name='items')
    meta_hash_sum = models.TextField(null=True)
    details = models.TextField(null=True)
    version = models.IntegerField()
    dt_modification = models.DateTimeField()
    dt_initialization = models.DateTimeField()
    internal_details = models.TextField(default='', blank=True)
    def delete(self, *args, **kwargs):
        data_item = self.data
        super(Item, self).delete(*args, **kwargs)
        data_item.maybe_delete()
    def maybe_delete(self):
        data_deleted = self.data.maybe_delete()
        if data_deleted==False:
            groups = self.groups.all()
            if len(groups)==0:
                self.delete()
                return True
            else:
                return False
        return True

class Group(models.Model):
    creator = models.ForeignKey('person.Person', related_name='groups_created_by_me')
    dt_initialization = models.DateTimeField()
    name = models.CharField(max_length=100)
    items = models.ManyToManyField('Item', related_name='groups')
    is_private = models.BooleanField(default=True)
    internal_details = models.TextField(default='', blank=True)
    group_type = models.CharField(max_length=100, blank=True, default='')
    def __unicode__(self):
        return '%s | %i roles | %i items' % (self.name, len(self.roles.all()), len(self.items.all()))
    def get_all_needed_pubkeys(self, me):
        try:
            my_role = self.roles.get(person=me)
        except:
            return None, 'needed role for user %s is not found' % me.email
        if my_role.access_add_file()==False:
            return None, 'user %s does not have permission to add file for group %i' % (me.email, self.id)
        result = []
        roles = self.roles.all()
        for role in roles:
            if role.access_read_file()==False:
                continue
            role_devices = role.person.devices.all()
            for d in role_devices:
                result.append({
                    'group_id': self.id,
                    'email': role.person.email,
                    'device_name': d.name,
                    'device_id': d.id,
                    'pub_key': d.pub_key
                })
        return result, None
    def get_needed_accesses_for_person(self, my_device):
        me = my_device.owner
        try:
            my_role = self.roles.get(person=me)
        except:
            return None, 'needed role for user %s is not found' % me.email
        if my_role.access_add_person()==False:
            return None, 'user %s does not have permission to add person for group %i' % (me.email, self.id)
        cypher_keys_dict = {}
        for item in self.items.all():
            my_accesses = item.data.accesses.filter(device=my_device)
            if len(my_accesses)==0:
                continue
            m = {
                'data_item_id': item.data.id,
                'cypher_key': my_accesses[0].cypher_key
            }
            cypher_keys_dict[item.data.id] = m
        return cypher_keys_dict.values()
    def missing_cypher_accesses(self, my_device):
        me = my_device.owner
        missings = []
        try:
            my_role = self.roles.get(person=me)
        except:
            return None, 'needed role for user %s is not found' % me.email
        if my_role.access_add_file()==False:
            return None, 'user %s does not have permission to add file for group %i' % (me.email, self.id)
        devices = []
        for role in self.roles.all():
            if (role.access_read_file() == True) & (role != my_role):
                for device in role.person.devices.all():
                    devices.append(device)
        items = self.items.all()
        for device in devices:
            for item in items:
                try:
                    him_access = item.data.accesses.get(device=device)
                    continue
                except:
                    pass
                try:
                    my_access = item.data.accesses.get(device=my_device)
                    missings.append({
                        'user': device.owner.email,
                        'user_id': device.owner.id,
                        'device': device.name,
                        'device_id': device.id,
                        'data_item_id': item.data.id,
                        'group_name': self.name,
                        'group_id': self.id,
                        'cypher_key': my_access.cypher_key,
                        'pub_key': device.pub_key,
                    })
                except:
                    continue
        return missings, None
    def maybe_delete(self):
        if self.is_private:
            pass
        else:
            roles = self.roles.all()
            if (len(roles) == 0):
                items = self.items.all()
                for item in items:
                    self.items.remove(item)
                self.save()
                for item in items:
                    item.data.maybe_delete()
                self.delete()
                return True
        return False

class Role(models.Model):
    creator = models.ForeignKey('person.Person', related_name='roles_created_by_me')
    dt_initialization = models.DateTimeField()
    person = models.ForeignKey('person.Person', related_name='roles')
    group = models.ForeignKey('Group', related_name='roles')
    role_type = models.CharField(max_length=30)
    is_confirmed = models.BooleanField(default=False)
    internal_details = models.TextField(default='', blank=True)
    expiration_datetime = models.DateTimeField(blank=True, null=True)
    @classmethod
    def create_or_update(cls, creator, person, dt_initialization, group, role_type):
        def update_role_type(old_role_type, new_role_type):
            if ((old_role_type=='administrator') | (new_role_type=='administrator')):
                return 'administrator'
            else:
                return new_role_type
        try:
            role = Role.objects.get(person=person, group=group)
            role.role_type = update_role_type(role.role_type, role_type)
            role.save()
        except Role.DoesNotExist:
            role = Role.objects.create(creator=creator,
                person=person,
                dt_initialization=dt_initialization,
                group=group,
                role_type=role_type,
                is_confirmed=False)
            role.save()
        return role
    def __unicode__(self):
        return '%s | %s - %s | %s' % (self.person.email, str(self.group_id), self.group.name, self.role_type)
    def access_add_file(self):
        if self.role_type=='administrator':
            return True
        return False
    def access_remove_file(self):
        if self.role_type=='administrator':
            return True
        return False
    def access_read_file(self):
        return True
    def access_add_person(self):
        if self.role_type=='administrator':
            return True
        return False

class Access(models.Model):
    creator = models.ForeignKey('person.Person', related_name='accesses_created_by_me')
    dt_initialization = models.DateTimeField()
    item = models.ForeignKey('DataItem', related_name='accesses')
    device = models.ForeignKey('person.Device', related_name='accesses')
    cypher_key = models.TextField()
    internal_details = models.TextField(default='', blank=True)
    def __unicode__(self):
        return '%s | %s' % (str(self.id), self.cypher_key[:40])
    @classmethod
    def create_or_update(cls, creator, data_item, device, cypher_key):
        try:
            access = device.accesses.get(item=data_item, device=device)
            access.creator = creator
            access.dt_initialization = datetime.now().replace(tzinfo=utc)
            access.cypher_key = cypher_key
            access.save()
        except Access.DoesNotExist:
            access = Access.objects.create(creator=creator,
                dt_initialization=datetime.now().replace(tzinfo=utc),
                item=data_item,
                device=device,
                cypher_key=cypher_key)
            access.save()
        return access
