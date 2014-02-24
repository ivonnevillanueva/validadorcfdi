from django.conf.urls import patterns, include, url
from django.conf import settings
from cfdi import views
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
url(r'^$', views.validador,name='validador'),
	
)
if settings.DEBUG:
	urlpatterns += patterns('',
		(r'^(?P<path>.*)$', 'django.views.static.serve', {
        'document_root': settings.STATIC_ROOT}))