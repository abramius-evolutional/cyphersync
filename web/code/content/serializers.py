from rest_framework import serializers
import person.serializers
import models

class GroupSerializer(serializers.ModelSerializer):
    dt_initialization = serializers.SerializerMethodField('m_dt_initialization')
    users = serializers.SerializerMethodField('m_users')
    creator = person.serializers.PersonLightSerializer()
    class Meta:
        model = models.Group
        fields = (
            'id',
            'creator',
            'name',
            'is_private',
            'users',
            'dt_initialization',
            'group_type',
        )
    def m_dt_initialization(self, obj):
        return obj.dt_initialization.strftime('%d-%m-%y %H:%M')
    def m_users(self, obj):
        group_users = []
        for role in obj.roles.all():
            p = role.person
            setattr(p, 'role_type', role.role_type)
            group_users.append(p)
        return person.serializers.PersonLightSerializer(group_users, many=True).data

class DataItemSerializer(serializers.ModelSerializer):
    dt_initialization = serializers.SerializerMethodField('m_dt_initialization')
    def m_dt_initialization(self, obj):
        return obj.dt_initialization.strftime('%d-%m-%y %H:%M')
    class Meta:
        model = models.DataItem
        fields = (
            'id',
            'aws_info',
            'version',
            'hash_sum',
            'dt_initialization'
        )

# class MetaItemSerializer(serializers.ModelSerializer):
#     dt_initialization = serializers.SerializerMethodField('m_dt_initialization')
#     dt_modification = serializers.SerializerMethodField('m_dt_modification')
#     def m_dt_initialization(self, obj):
#         return obj.dt_initialization.strftime('%d-%m-%y %H:%M')
#     def m_dt_modification(self, obj):
#         return obj.dt_modification.strftime('%d-%m-%y %H:%M')
#     class Meta:
#         model = models.MetaItem
#         fields = (
#             'details',
#             'version',
#             'hash_sum',
#             'dt_initialization',
#             'dt_modification'
#         )

class ItemSerializer(serializers.ModelSerializer):
    data = DataItemSerializer()
    meta = serializers.SerializerMethodField('m_meta')
    cypher_key = serializers.SerializerMethodField('m_cypher_key')
    details = serializers.SerializerMethodField('m_details')
    class Meta:
        model = models.Item
        fields = (
            'id',
            'data',
            'meta',
            'cypher_key',
            'details'
        )
    def m_cypher_key(self, obj):
        try:
            return obj.cypher_key
        except:
            return ''
    def m_details(self, obj):
        try:
            return obj.group_details
        except:
            return ''
    def m_meta(self, obj):
        return {
            'hash_sum': obj.meta_hash_sum,
            'details': obj.details,
            'version': obj.version,
            'dt_initialization': obj.dt_initialization.strftime('%d-%m-%y %H:%M'),
            'dt_modification': obj.dt_modification.strftime('%d-%m-%y %H:%M')
        }

class RoleSerializer(serializers.ModelSerializer):
    group = GroupSerializer()
    expiration_datetime = serializers.SerializerMethodField('m_expiration_datetime')
    class Meta:
        model = models.Role
        fields = (
            'id',
            'role_type',
            'group',
            'is_confirmed',
            'expiration_datetime'
        )
    def m_expiration_datetime(self, obj):
        if obj.expiration_datetime:
            return obj.expiration_datetime.strftime('%d-%m-%y %H:%M')
        else:
            return None