from django.http import JsonResponse
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from login.forms import SignUpForm
from django.contrib import messages
import json
from login.models import Profile

@csrf_exempt
def hostSignUp(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()  # load the profile instance created by the signal
            user.profile.userType = int(0)
            user.save()
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=user.username, password=raw_password)
            login(request, user)

            return HttpResponse() # TODO: Should I respond with a 200 OK for both the GET and POST response.
        else:
            return JsonResponse(form.errors)
    else:
        return HttpResponse()