from django.conf.urls import include, url
from django.conf import settings

import views

urlpatterns = [
    url(r'^daily_task/', views.daily_task),
    url(r'^hourly_task/', views.hourly_task),
    url(r'^minutely_task/', views.minutely_task),
    url(r'^info/', views.info),
]