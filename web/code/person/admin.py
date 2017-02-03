from django.contrib import admin
import models

class PersonAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'email',
        'creation_datetime',
        'is_active',
        'is_confirmed',
    )

class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'owner',
        'device_id',
        'name',
        'vendor',
        'push_identifier',
    )

admin.site.register(models.Person, PersonAdmin)
admin.site.register(models.Device, DeviceAdmin)