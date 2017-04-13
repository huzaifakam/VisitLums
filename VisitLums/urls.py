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
    url(r'^$', auth_views.login, name='login'),
    url(r'^logout/$', logout_page),
    url(r'^accounts/login/$', auth_views.login, name='login'), # If user is not login it will redirect to login page
    url(r'^register/$', register),
    url(r'^register/success/$', register_success),
    url(r'^home/$', home),
    url(r'^host/$', hostLogin),
    url(r'^host/dashboard/$', hostDashboard),
    url(r'^host/request/$', hostRequest),
    url(r'^host/requestSpecial/$', hostRequestSpecial),
    url(r'^host/settings/$', hostSettings),
    url(r'^host/logout/$', hostLogout),
    url(r'^guard/$', guardLogin),
    url(r'^guard/logout/$', guardLogout),
    url(r'^admin/$', adminLogin),
    url(r'^admin/dashboard/$', adminDashboard),
    url(r'^admin/request/$', adminRequest),
    url(r'^admin/requestSpecial/$', adminRequestSpecial),
    url(r'^admin/settings/$', adminSettings),
    url(r'^admin/logout/$', adminLogout),
]