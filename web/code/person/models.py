from django.db import models
import os

class Device(models.Model):
    owner = models.ForeignKey('Person', related_name='devices')
    device_id = models.CharField(max_length=36)
    name = models.CharField(max_length=50, blank=True, default='')
    pub_key = models.CharField(max_length=500, unique=True)
    details = models.TextField(blank=True, default='{}')
    internal_details = models.TextField(default='', blank=True)
    vendor = models.CharField(max_length=30, default='')
    push_identifier = models.TextField(default='')
    def send_push(self, message):
        pass
    def __unicode__(self):
        return self.device_id[:4] + ' ' + self.name

def avatar_upload_function(instance, filename):
    name = 'user%i_avatar_%s' % (instance.id, filename)
    return os.path.join('avatar/', name)

class Person(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=50, unique=True)
    details = models.TextField(blank=True, default='{}')
    password = models.CharField(max_length=100)
    avatar = models.ImageField(upload_to=avatar_upload_function, null=True, blank=True)
    creation_datetime = models.DateTimeField()
    is_confirmed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    internal_details = models.TextField(default='', blank=True)
    def __unicode__(self):
        return self.email
