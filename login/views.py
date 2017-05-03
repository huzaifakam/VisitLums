from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from login.forms import SignUpForm, AuthenticationForm
from django.contrib import messages
from login.models import User, Profile
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from login.tokens import accountActivationToken
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.auth import logout

import json

@csrf_exempt
@login_required(login_url='/host/login')
def hostHome(request):
    print ("hostHome")
    return HttpResponse()

@csrf_exempt
def hostLogin(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = authenticate(username = request.POST['username'], password = request.POST['password'])
            if user is not None:
                login(request, user)
                return HttpResponseRedirect('/host/dashboard') # Goto Dashboard            
        else:
            return JsonResponse(form.errors)
    else:
        return HttpResponse()

@csrf_exempt
def hostLogout(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        logout(request)
    return HttpResponseRedirect('/host/login')


@csrf_exempt
def hostSignUp(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            
            user.refresh_from_db()  # load the profile instance created by the signal
            user.profile.userType = int(0) # 0 -> Hosts, 1 -> Admins, 2 -> Guards
            user.save()

            currentSite = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = accountActivationToken.make_token(user)
            message = 'Hi ' + str(user.get_full_name()) + ',\n\n' + 'Please click on the link below to confirm your registration:\n\n' + ('http://' + currentSite.domain + '/host/activate/' + str(uid.decode('utf-8')) + '/' + str(token) + '/')
            subject = 'VisitLUMS Account Activation Link'

            send_mail(subject, message, 'kvmmaster3@gmail.com', [user.email])
            return HttpResponse()
        else:
            return JsonResponse(form.errors)
    else:
        return HttpResponse()

@csrf_exempt
def hostActivate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and accountActivationToken.check_token(user, token):
        user.is_active = True
        user.profile.email_confirmed = True
        user.save()
        login(request, user)
        return HttpResponseRedirect('/host/dashboard')
    else:
        return HttpResponse() # TODO: Handle Invalid Activation

@csrf_exempt
def hostDashboard(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        # TODO: Get these numbers from the database!
        return JsonResponse({'user': request.user.get_full_name(), 'total': 2, 'approved': 3, 'pending': 4, 'visits': 5})
    else:
        return HttpResponseRedirect('/host/login')