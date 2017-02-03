from django.contrib import admin
import models

class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user',
                    'device',
                    'dt_expiration',
                    'token',)

class ConfirmationTokenAdmin(admin.ModelAdmin):
    list_display = ('user',
                    'dt_initialization',
                    'dt_expiration',
                    'token')

class ChangePasswordTokenAdmin(admin.ModelAdmin):
    list_display = ('user',
                    'dt_initialization',
                    'dt_expiration',
                    'token')


admin.site.register(models.AccessToken, AccessTokenAdmin)
admin.site.register(models.ConfirmationToken, ConfirmationTokenAdmin)
admin.site.register(models.ChangePasswordToken, ChangePasswordTokenAdmin)