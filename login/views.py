from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from login.forms import SignUpForm, AuthenticationForm
from django.contrib import messages
from login.models import User, Profile, Requests, Visitor, RequestedGuests, Visits, GuestsPerVisit
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from login.tokens import accountActivationToken
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.auth import logout
from django.http import QueryDict

import json
from datetime import datetime

# SuperUser
try:
    if (len(list(Profile.objects.filter(userType=3))) == 0):
        superUserDict = {'first_name': "Super",
            'last_name': "User",
            'password1': "password",
            'password2': "password",
            'username': "superuser"
        }

        qdict = QueryDict('', mutable=True)
        qdict.update(superUserDict)
        form = SignUpForm(qdict)

        if form.is_valid() == True:
            print ("Adding SuperUser!")
            user = form.save(commit=False)
            user.is_active = True
            user.save()
            user.refresh_from_db()  # load the profile instance created by the signal
            user.profile.userType = 3 # 0 -> Hosts, 1 -> Admins, 2 -> Guards
            user.profile.email_confirmed = True
            user.save()
except Exception as E:
    pass

# Login
@csrf_exempt
@login_required(login_url='/login')
def home(request):
    return HttpResponse()

# Logout
@csrf_exempt
def login_(request):
    if request.method == 'POST':
        json_data = json.loads(request.body.decode('utf-8'))
        dicto = {'username': json_data['username'], 'password': json_data['password']}
        qdict = QueryDict('', mutable=True)
        qdict.update(dicto)
        form = AuthenticationForm(data=qdict)
        if form.is_valid():
            user = authenticate(username = json_data['username'], password = json_data['password'])
            if user is not None:
                login(request, user)
                if user.profile.userType == 0:
                    return JsonResponse({"userType": 0, 'user': request.user.get_full_name()}) # Host
                elif user.profile.userType == 1:
                    return JsonResponse({"userType": 1, 'user': request.user.get_full_name()}) # Admin
                elif user.profile.userType == 2:
                    return JsonResponse({"userType": 2, 'user': request.user.get_full_name()}) # Guard
                elif user.profile.userType == 3:
                    return JsonResponse({"userType": 3, 'user': request.user.get_full_name()}) # SuperUser
        else:
            return JsonResponse(form.errors)
    else:
        return HttpResponse(status=401)

# Logout
@csrf_exempt
def logout_(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        logout(request)
    return HttpResponse("Logged Out!")

# Host Signup
@csrf_exempt
def hostSignUp(request):
    if request.method == 'POST':
        json_data = json.loads( request.body.decode('utf-8'))
        dicto = {'first_name': json_data['first_name'],
         'last_name': json_data['last_name'],
         'password1': json_data['password1'],
         'password2': json_data['password2'],
         'username': json_data['username']
         }
        qdict = QueryDict('', mutable=True)
        qdict.update(dicto)
        form = SignUpForm(qdict)
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

# Host Signup
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
        return HttpResponse(status=401)

@csrf_exempt
def hostNewGuestRequest(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        if request.method == 'POST':
            jsonData = json.loads( request.body.decode('utf-8'))

            host = request.user.profile
            expectedArrivalDate = jsonData['date']
            purposeVisit = jsonData['purpose']
            numGuests = len(jsonData['visitors'])
            specialRequest = jsonData['specialRequest']
            admin = None
            approval = 'Pending'
            approvalTime = None

            if specialRequest == 0:
                numGuests = len(jsonData['visitors'])
            elif specialRequest == 1:
                numGuests = jsonData['numGuests']

            r = Requests(host=host, expectedArrivalDate=expectedArrivalDate, purposeVisit=purposeVisit, numGuests=numGuests, specialRequest=specialRequest, admin=admin, approval=approval, approvalTime=approvalTime)
            r.save()

            for i in (jsonData['visitors']):
                first_name = i['first_name']
                last_name = i['last_name']
                cnic = i['cnic']
                mobile = i['mobile']

                v = Visitor(first_name=first_name, last_name=last_name, cnic=cnic, mobile=mobile)
                v.save()
                rG = RequestedGuests(request=r, visitor=v)
                rG.save()

            return HttpResponse("Request Added")
        else:
            return JsonResponse({'user': request.user.get_full_name()})
    else:
        return HttpResponse(status=401)

@csrf_exempt
def adminAllRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        results = {'requests':[]}
        if request.method == 'GET':
            for i in list(Requests.objects.all()):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'host': i.host.user.get_full_name(), 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)        
    else:
        return HttpResponse(status=401)

@csrf_exempt
def adminApprovedRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        results = {'requests':[]}
        if request.method == 'GET':
            for i in list(Requests.objects.filter(approval="Approved")):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'host': i.host.user.get_full_name(), 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results) 
    else:
        return HttpResponse(status=401)

@csrf_exempt
def adminPendingRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        results = {'requests':[]}
        if request.method == 'GET':
            for i in list(Requests.objects.filter(approval="Pending")):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'host': i.host.user.get_full_name(), 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def adminFailedRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        results = {'requests':[]}
        if request.method == 'GET':
            for i in list(Requests.objects.filter(approval="Denied")):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'host': i.host.user.get_full_name(), 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def adminCompletedVisits(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        return HttpResponse() # TODO
    else:
        return HttpResponse(status=401)

@csrf_exempt
def hostAllRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        results = {'requests':[]}
        if request.method == 'GET':
            user = Profile.objects.get(user=User.objects.get(username=request.user))
            for i in list(Requests.objects.filter(host=user)):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)  

@csrf_exempt
def hostApprovedRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        results = {'requests':[]}
        if request.method == 'GET':
            user = Profile.objects.get(user=User.objects.get(username=request.user))
            for i in list(Requests.objects.filter(approval='Approved', host=user)):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def hostPendingRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        results = {'requests':[]}
        if request.method == 'GET':
            user = Profile.objects.get(user=User.objects.get(username=request.user))
            for i in list(Requests.objects.filter(approval='Pending', host=user)):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def hostFailedRequests(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        results = {'requests':[]}
        if request.method == 'GET':
            user = Profile.objects.get(user=User.objects.get(username=request.user))
            for i in list(Requests.objects.filter(approval='Denied', host=user)):
                visitorNames = [str(x.visitor.first_name) + ' ' + str(x.visitor.last_name)  for x in list(RequestedGuests.objects.filter(request=i))]
                results['requests'].append({'id': i.id, 'name': visitorNames, 'date': i.expectedArrivalDate, 'status': i.approval})
            return JsonResponse(results)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def hostCompletedVisits(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 0):
        results = {'visits':[]} # TODO
        if request.method == 'GET':
            user = Profile.objects.get(user=User.objects.get(username=request.user))

            for i in list(Visits.objects.filter(request__host=user)):
                print(i) # TODO: Complete it!
            return JsonResponse(results)
    else:
        return HttpResponse(status=401) 

@csrf_exempt
def dashboard(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        user = Profile.objects.get(user=User.objects.get(username=request.user))

        if request.method == 'GET':
            if request.user.profile.userType == 0:
                total = len(list(Requests.objects.filter(host=user)))
                approved = len(list(Requests.objects.filter(host=user, approval='Approved')))
                pending = len(list(Requests.objects.filter(host=user, approval='Pending')))
                visits = 5 # TODO: Remove this hardcoded number.

                return JsonResponse({'userType': 0, 'user': request.user.get_full_name(), 'total': total, 'approved': approved, 'pending': pending, 'visits': visits})

            elif request.user.profile.userType == 2: # Admin
                total = len(list(Requests.objects.all()))
                approved = len(list(Requests.objects.filter(approval='Approved')))
                pending = len(list(Requests.objects.filter(approval='Pending')))
                visits = 5 # TODO: Remove this hardcoded number.
                return JsonResponse({'userType': 2, 'user': request.user.get_full_name(), 'total': total, 'approved': approved, 'pending': pending, 'visits': 5})

            elif request.user.profile.userType == 1: # Guard
                hostList = {'hosts':[]}
                
                for i in (list(Requests.objects.filter(approval='Approved'))):
                    hostList['hosts'].append({'id': i.id, 'name': (i.host.user.get_full_name()), 'date': i.expectedArrivalDate})
                return JsonResponse(hostList)

            elif request.user.profile.userType == 3:
                return JsonResponse({'userType': 3, 'user': request.user.get_full_name()})
    else:
        return HttpResponse(status=401)

# ---------------------------------------------------------------------------------------------------------------------------------------------------------

@csrf_exempt
def adminRequestCheck(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 2):
        if (request.method == 'POST'):
            jsonData = json.loads( request.body.decode('utf-8'))
            r = Requests.objects.get(id=jsonData['requestID'])
            r.approval = jsonData['approval']
            r.approvalTime = datetime.now()
            r.admin = Profile.objects.get(user=User.objects.get(username=request.user))
            r.save()
            return HttpResponse("Request Updated")
        else:
            return HttpResponse()
    else:
        return HttpResponse(status=401)

@csrf_exempt
def guardGetRequest(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 1):
        if (request.method == 'POST'):
            result = {'visitors': []}
            jsonData = json.loads( request.body.decode('utf-8'))
            r = Requests.objects.get(id=jsonData['id'])

            result['host'] = r.host.user.get_full_name()
            result['numGuest'] = r.numGuests
            result['admin'] = r.admin.user.get_full_name()
            result['requestType'] = r.specialRequest
            result['requestID'] = r.id

            for i in list(RequestedGuests.objects.filter(request=r)):
                result['visitors'].append({'visitorID': i.visitor.id, 'first_name':i.visitor.first_name, 'last_name':i.visitor.last_name, 'cnic':i.visitor.cnic, 'mobile':i.visitor.mobile})
            return JsonResponse(result)
        else:
            return HttpResponse()
    else:
        return HttpResponse(status=401)

@csrf_exempt
def guardMarkEntry(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 1):
        if (request.method == 'POST'):
            jsonData = json.loads( request.body.decode('utf-8'))
            r = Requests.objects.get(id=jsonData['id'])
            v = Visits(request=r, entryTime=datetime.now(), exitTime=None)
            v.save()
        return HttpResponse()
    else:
        return HttpResponse(status=401)

@csrf_exempt
def guardMarkExit(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 1):
        if (request.method == 'POST'):
            jsonData = json.loads( request.body.decode('utf-8'))
            r = Requests.objects.get(id=jsonData['id'])
            v = Visits.objects.get(request=r)
            v.exitTime = datetime.now()
            v.save()
        return HttpResponse()
    else:
        return HttpResponse(status=401)

@csrf_exempt
def guardMarkVisitor(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 1):
        if (request.method == 'POST'):
            user = Profile.objects.get(user=User.objects.get(username=request.user))

            jsonData = json.loads( request.body.decode('utf-8'))
            r = Requests.objects.get(id=jsonData['requestID'])
            v = Visits.objects.get(request=r)

            visitor = Visitor.objects.get(id=jsonData['visitorID'])

            temp = GuestsPerVisit(visit=v, visitor=visitor, guard=user)
            temp.save()
        return HttpResponse()
    else:
        return HttpResponse(status=401)
# -----------------------------------------------------------------------------------------------------------

@csrf_exempt
def changeSettings(request):
    if ((request.user.is_authenticated() and request.user.is_active)):
        if request.method == 'POST':
            json_data = json.loads( request.body.decode('utf-8'))
            password1 = json_data['password1']
            password2 = json_data['password2']

            if request.user.check_password(password1):
                request.user.set_password(password2)
                request.user.save()
                return HttpResponse()
            else:
                return JsonResponse({'password1': "Invalid Password"})
    else:
        return HttpResponse(status=401)

@csrf_exempt
def superuserRequestAdd(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 3):
        if request.method == 'POST':
            json_data = json.loads( request.body.decode('utf-8'))
            dicto = {'first_name': json_data['first_name'],
             'last_name': json_data['last_name'],
             'password1': json_data['password'],
             'password2': json_data['password'],
             'username': json_data['username'] # TODO: Change username to email.
             }
            qdict = QueryDict('', mutable=True)
            qdict.update(dicto)
            form = SignUpForm(qdict)

            if form.is_valid():
                user = form.save(commit=False)
                user.is_active = True
                user.save()
                user.refresh_from_db()  # load the profile instance created by the signal
                user.profile.userType = json_data['userType'] # 0 -> Hosts, 1 -> Guards, 2 -> Admin
                user.profile.email_confirmed = True
                user.save()
        return HttpResponse("Added Record")
    else:
        return HttpResponse(status=401)


@csrf_exempt
def superuserAdminList(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 3):
        admins = {'admins': []}

        for i in list(Profile.objects.filter(userType=2)):
            admins['admins'].append({'first_name': i.user.first_name, 'last_name': i.user.last_name, 'email': i.user.username})
        return JsonResponse(admins)
    else:
        return HttpResponse(status=401)

@csrf_exempt
def superuserGuardList(request):
    if ((request.user.is_authenticated() and request.user.is_active) and request.user.profile.userType == 3):
        guards = {'guards': []}

        for i in list(Profile.objects.filter(userType=1)):
            guards['guards'].append({'first_name': i.user.first_name, 'last_name': i.user.last_name, 'email': i.user.username})
        return JsonResponse(guards)
    else:
        return HttpResponse(status=401)