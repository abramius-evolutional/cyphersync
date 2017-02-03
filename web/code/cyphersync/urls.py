from django.conf.urls import include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings

import tokenauth.urls
import content.urls
import internal_api.urls
import person.urls

urlpatterns = [

    url(r'^admin/', include(admin.site.urls)),
    url(r'^auth/', include(tokenauth.urls)),
    url(r'^person/', include(person.urls)),
    url(r'^content/', include(content.urls)),
    url(r'^internal_api/', include(internal_api.urls)),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)\
  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
