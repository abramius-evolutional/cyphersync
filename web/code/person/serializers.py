from rest_framework import serializers
import models

class PersonSerializer(serializers.ModelSerializer):
    creation_datetime = serializers.SerializerMethodField('m_creation_datetime')
    avatar = serializers.SerializerMethodField('m_avatar')
    class Meta:
        model = models.Person
        fields = (
            'id',
            'email',
            'name',
            'details',
            'avatar',
            'creation_datetime',
            'is_confirmed',
        )
    def m_creation_datetime(self, obj):
        return obj.creation_datetime.strftime('%d-%m-%y %H:%M')
    def m_avatar(self, obj):
        try:
            url = obj.avatar.url
        except:
            url = ''
        return url

class PersonLightSerializer(serializers.ModelSerializer):
    role_type = serializers.SerializerMethodField('m_role_type')
    avatar = serializers.SerializerMethodField('m_avatar')
    class Meta:
        model = models.Person
        fields = (
            'id',
            'email',
            'name',
            'avatar',
            'role_type',
        )
    def m_role_type(self, obj):
        try:
            return obj.role_type
        except:
            return None
    def m_avatar(self, obj):
        try:
            url = obj.avatar.url
        except:
            url = ''
        return url

class DeviceSerializer(serializers.ModelSerializer):
    owner = PersonSerializer()
    class Meta:
        model = models.Device
        fields = (
            'id',
            'name',
            'pub_key',
            'push_identifier',
            'owner',
            'details',
            'vendor',
        )