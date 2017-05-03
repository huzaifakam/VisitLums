"""VisitLums URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))"""
from django.conf.urls import url, include
from login.views import *
from django.contrib.auth import views as auth_views

 
urlpatterns = [
    # url(r'^$', auth_views.login, name='login'),
    # url(r'^host/login/$', hostLogin),
    url(r'^host/signUp/$', hostSignUp),
    url(r'^host/accountActivationSent/$', hostAccountActivationSent),
    url(r'^host/activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        hostActivate, name='activate'),
    # url(r'^host/dashboard/$', hostDashboard),
    # url(r'^host/accountSettings/$', hostAccountSettings),
    # url(r'^host/newGuestRequest/$', hostNewGuestRequest),
    # url(r'^host/specialGuestRequest/$', specialGuestRequest),
    # url(r'^host/view/$', hostView),
]