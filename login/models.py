from __future__ import unicode_literals
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	userType = models.IntegerField(default=0)
	email_confirmed = models.BooleanField(default=False)

@receiver(post_save, sender=User)
def update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()

class Requests(models.Model):
    Pending = 'Pending'
    Approved = 'Approved'
    Denied = 'Denied'

    approvalChoices = (
        (Pending, 'Pending'),
        (Approved, 'Approved'),
        (Denied, 'Denied'),
    )

    host = models.ForeignKey(Profile, on_delete=models.CASCADE)
    dateRequested = models.DateTimeField('Date Requested', auto_now_add=True)
    expectedArrivalDate = models.DateTimeField('Expected Arrival Date', blank=True, null=True)
    approval = models.CharField(max_length=8, choices=approvalChoices, default=Pending)
    approvalTime = models.DateTimeField('Approval Time', blank=True, null=True)
    purposeVisit = models.CharField(max_length=1000)
    numGuests = models.IntegerField(default=1)
    admin = models.ForeignKey(Profile, related_name='ADMIN', blank=True, null=True)
    specialRequest = models.BooleanField()

class Visitor(models.Model):
	first_name = models.CharField(max_length=50)
	last_name = models.CharField(max_length=50)
	cnic = models.CharField(max_length=50)
	mobile = models.CharField(max_length=50)

class RequestedGuests(models.Model):
	request = models.ForeignKey(Requests, on_delete=models.CASCADE)
	visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE)

class Visits(models.Model):
	request = models.OneToOneField(Requests, on_delete=models.CASCADE)
	entryTime = models.DateTimeField(blank=True, null=True)
	exitTime = models.DateTimeField(blank=True, null=True)

class GuestsPerVisit(models.Model):
	visit = models.ForeignKey(Visits)
	visitor = models.ForeignKey(Visitor)
	guard = models.ForeignKey(Profile, related_name='Guard', blank=True, null=True)