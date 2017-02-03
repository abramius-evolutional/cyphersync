from django.contrib import admin
import models

class GroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'creator', 'is_private', 'name')



admin.site.register(models.DataItem)
admin.site.register(models.Item)
admin.site.register(models.Group, GroupAdmin)
admin.site.register(models.Role)
admin.site.register(models.Access)
