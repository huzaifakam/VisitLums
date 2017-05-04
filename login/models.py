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
    cnic = models.CharField(max_length=25)
    visitorFirstName = models.CharField(max_length=25)
    visitorLastName = models.CharField(max_length=25)
    dateRequested = models.DateTimeField('Date Requested', auto_now_add=True)
    expectedArrivalDate = models.DateTimeField('Expected Arrival Date', null=True)
    approval = models.CharField(max_length=8, choices=approvalChoices, default=Pending)
    purposeVisit = models.CharField(max_length=1000)
    approvalTime = models.DateTimeField('Approval Time', null=True)
    numGuests = models.IntegerField(default=1)
    admin = models.ForeignKey(Profile, related_name='ADMIN', blank=True, null=True)
    guard = models.ForeignKey(Profile, related_name='GUARD', blank=True, null=True)
    photo = models.ImageField()
    specialRequest = models.BooleanField()