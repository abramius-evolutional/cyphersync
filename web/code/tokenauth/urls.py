from django.conf.urls import include, url
from django.conf import settings

import views

urlpatterns = [
    url(r'^registration/', views.registration),
    url(r'^login/', views.login),
    url(r'^change/', views.change),
    url(r'^confirm_email/([\w\d-]+)', views.confirm),
    url(r'^logout/', views.logout),
    url(r'^change_password_request/', views.change_password_request),
    url(r'^change_password/([\w\d-]+)', views.change_password),
    url(r'^details/', views.details),
    url(r'^setpushidentifier/', views.set_push_id),
]

if settings.DEBUG:
    urlpatterns += [
        url(r'^delete_user/', views.__delete_person),
    ]
