from django.conf.urls import include, url
from django.conf import settings

import views

urlpatterns = [
    url(r'^create_group/', views.create_group),
    url(r'^roles/', views.get_roles),
    url(r'^add_file/', views.add_file),
    url(r'^files/', views.get_files),
    url(r'^add_role/', views.add_role),
    url(r'^confirm_role/', views.confirm_role),
    url(r'^delete_role/', views.delete_role),
    url(r'^delete_group/', views.delete_group),
    url(r'^change_file/', views.change_file),
    url(r'^delete_file/', views.delete_file),
    url(r'^check_accesses/', views.check_accesses),
    url(r'^add_cypher_access/', views.add_cypher_access),
    url(r'^actual_aws_info/', views.actual_aws_info),
]