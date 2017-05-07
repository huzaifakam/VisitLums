from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from login.forms import SignUpForm, AuthenticationForm, RequestForm
from django.contrib import messages
from login.models import User, Profile, Requests
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from login.tokens import accountActivationToken
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.auth import logout

import json

@csrf_exempt
@login_required(login_url='/login')
def home(request):
    print ("hostHome")
    return HttpResponse()

@csrf_exempt
def login_(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = authenticate(username = request.POST['username'], password = request.POST['password'])
            if user is not None:
                login(request, user)
                if user.profile.userType == 0:
                    return HttpResponseRedirect('/host/dashboard') # Goto Dashboard
                elif user.profile.userType == 1:
                    return HttpResponseRedirect('/admin/dashboard') # Goto Admin Dashboard 
                elif user.profile.userType == 2:
                    return HttpResponseRedirect('/guard/dashboard') # Goto Guard Dashboard
        else:
            return JsonResponse(form.errors)
    else:
        return HttpResponse()

@csrf_exempt
def logout_(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        logout(request)
    return HttpResponseRedirect('/login')


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

            send_mail(subject, message, 'kvmmaster3@gmail.com', [user.username])
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
def dashboard(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        if request.user.profile.userType == 0: # TODO: Get these numbers from the database!
            total = (len(Requests.objects.all()))
            approved = (len(Requests.objects.filter(approval='Approved')))
            pending = (len(Requests.objects.filter(approval='Pending')))
            visits = 5 # TODO: Remove this hardcoded number.

            return JsonResponse({'userType': 0, 'user': request.user.get_full_name(), 'total': total, 'approved': approved, 'pending': pending, 'visits': visits})
        elif request.user.profile.userType == 1:
            print("ADMIN") # TODO: Complete This
            return JsonResponse({'userType': 1, 'user': request.user.get_full_name(), 'total': 2, 'approved': 3, 'pending': 4, 'visits': 5})
        elif request.user.profile.userType == 2:
            print("GUARD")
            return JsonResponse({'userType': 2, 'user': request.user.get_full_name(), 'total': 2, 'approved': 3, 'pending': 4, 'visits': 5})
    else:
        return HttpResponseRedirect('/login')

@csrf_exempt
def hostSettings(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        if request.method == 'POST':
            return HttpResponse() # TODO: Complete this POST Request.
        else:
            return JsonResponse({'user': request.user.get_full_name()})
    else:
        return HttpResponseRedirect('/login')


# def save_events_json(request):
#     if request.is_ajax():
#         if request.method == 'POST':
#             print 'Raw Data: "%s"' % request.body   
#     return HttpResponse("OK")

@csrf_exempt
def hostNewGuestRequest(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        if request.method == 'POST':
            # form = RequestForm(request.POST)
            print (request.body)
            json_data = json.loads( request.body.decode('utf-8'))
            print (json_data['date'])
            print (json_data['purpose'])
            print(len(json_data['visitors']))
            # print (form)
            return HttpResponse()

            # if form.is_valid():
            #     host = request.user.profile
            #     visitorFirstName = form.cleaned_data['first_name']
            #     visitorLastName = form.cleaned_data['last_name']
            #     expectedArrivalDate = form.cleaned_data['date']
            #     approval = 'Pending'
            #     cnic = form.cleaned_data['cnic']
            #     purposeVisit = form.cleaned_data['purpose']
            #     admin = None
            #     guard = None
            #     photo = form.cleaned_data['photo']
            #     specialRequest = form.cleaned_data['specialRequest']

            #     if form.cleaned_data['numGuests'] != None:
            #         numGuests = form.cleaned_data['numGuests']
            #     else:
            #         numGuests = 1

            #     r = Requests(host=host, visitorFirstName=visitorFirstName, visitorLastName=visitorLastName,
            #         expectedArrivalDate=expectedArrivalDate, approval=approval, cnic=cnic, numGuests=numGuests,
            #         purposeVisit=purposeVisit, admin=admin, guard=guard, photo=photo, specialRequest=specialRequest)
            #     r.save()

            #     return HttpResponse() # TODO: Where to go after saving a record?
            # else:
                # return JsonResponse(form.errors)
        else:
            return JsonResponse({'user': request.user.get_full_name()})
    else:
        return HttpResponseRedirect('/login')