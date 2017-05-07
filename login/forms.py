from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'password1', 'password2', 'username',)

# class RequestForm(forms.Form):
# 	first_name = forms.CharField(max_length=30, required=True)
# 	last_name = forms.CharField(max_length=30, required=True)
# 	cnic = forms.CharField(max_length=30, required=True)
# 	phone = forms.CharField(max_length=30, required=True)
# 	date = forms.DateTimeField(required=True)
# 	purpose = forms.CharField(max_length=500, required=True)
# 	specialRequest = forms.BooleanField(required=True)

# 	photo = forms.ImageField(required=False)
# 	numGuests = forms.IntegerField(required=False)



# class HostSettings(froms.Form):
	# typeSetting = forms.IntegerField(default=0 , required=True)
	# TODO: Complete this form.