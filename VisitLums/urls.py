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


# Host - CompletedVisits - Left
 
urlpatterns = [
    url(r'^$', home),
    url(r'^login/$', login_),
    url(r'^logout/$', logout_),
    url(r'^host/signup/$', hostSignUp),
    url(r'^host/activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        hostActivate, name='activate'),
    url(r'^host/dashboard/$', dashboard),
    url(r'^host/accountSettings/$', hostSettings),
    url(r'^host/newGuestRequest/$', hostNewGuestRequest),
    url(r'^host/specialGuestRequest/$', hostNewGuestRequest),
    url(r'^host/allRequests/$', hostAllRequests),
    url(r'^host/approvedRequests/$', hostApprovedRequests),
    url(r'^host/pendingRequests/$', hostPendingRequests),
    url(r'^host/failedRequests/$', hostFailedRequests),
    url(r'^host/completedVisits/$', hostCompletedVisits),

    url(r'^superuser/requestAdd/$', superuserRequestAdd),
    url(r'^superuser/adminList/$', superuserAdminList),
    url(r'^superuser/guardList/$', superuserGuardList),
    url(r'^superuser/settings/$', superuserChangeSettings),
    
    url(r'^admin/dashboard/$', dashboard),
    url(r'^admin/requestCheck/$', adminRequestCheck),

    url(r'^guard/dashboard/$', dashboard),
    url(r'^guard/getRequest/$', guardGetRequest),
    url(r'^guard/markEntry/$', guardMarkEntry),
    url(r'^guard/markExit/$', guardMarkExit)
]