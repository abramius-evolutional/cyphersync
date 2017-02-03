from django.conf.urls import include, url
from django.conf import settings

import views

urlpatterns = [
    url(r'^person_about/', views.person_about),
    url(r'^device_about/', views.device_about),
    url(r'^person_devices/', views.person_devices),
]