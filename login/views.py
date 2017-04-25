#views.py
from login.forms import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render_to_response, render
from django.http import HttpResponseRedirect
from django.template import RequestContext

from django.views.decorators.csrf import csrf_exempt

 
@csrf_protect
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
            username=form.cleaned_data['username'],
            password=form.cleaned_data['password1'],
            email=form.cleaned_data['email']
            )
            return HttpResponseRedirect('/register/success/')
    else:
        form = RegistrationForm()
    variables = RequestContext(request, {
    'form': form
    })
 
    return render(request, 'registration/register.html', {'form': form, })

@csrf_exempt
def frontPage(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
            email=form.cleaned_data['email'],
            password=form.cleaned_data['password']
            )
    else:
        form = LoginForm()
    return render(request, 'front-page.html', {'form': form,})

def hostLogin(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostLogin.html', {'form': form,})

def hostDashboard(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostDashboard.html', {'form': form,})

def hostRequest(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostRequest.html', {'form': form,})

def hostRequestSpecial(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostRequestSpecial.html', {'form': form,})

def hostSettings(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostSettings.html', {'form': form,})

def hostLogout(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'host/hostLogout.html', {'form': form,})

def guardLogin(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'guard/guardLogin.html', {'form': form,})

def guardLogout(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'guard/guardLogout.html', {'form': form,})

def adminLogin(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminLogin.html', {'form': form,})

def adminDashboard(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminDashboard.html', {'form': form,})

def adminRequest(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminRequest.html', {'form': form,})

def adminRequestSpecial(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminRequestSpecial.html', {'form': form,})

def adminSettings(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminSettings.html', {'form': form,})

def adminLogout(request):
    if request.method == 'POST':
        form = TempForm(request.POST)
    else:
        form = TempForm()

    return render(request, 'admin/adminLogout.html', {'form': form,})


def registerVisitor(request):
    if request.method == 'POST':
        form = VisitorForm(request.POST)

        if form.is_valid():
            return HttpResponseRedirect()
    else:
        form = VisitorForm()

    variables = RequestContext(request, {
        'form': form
    })

    return render(request, 'registration/admin.html', {'form': form, })
 
def register_success(request):
    return render_to_response(
    'registration/success.html',
    )
 
def logout_page(request):
    logout(request)
    return HttpResponseRedirect('/')
 
@login_required
def home(request):
    return render_to_response(
    'home.html',
    { 'user': request.user }
    )