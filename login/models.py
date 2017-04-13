from django.db import models

# Create your models here.

class Person(models.Model):
    firstName = models.CharField(max_length=25)
    lastName = models.CharField(max_length=25) # Check on how inheritence works!
    CNIC = models.CharField(max_length=25)
    mobile = models.CharField(max_length=20)

    def __str__(self):
        return (self.firstName + " " + self.lastName + ", " + str(self.mobile) + ", " + self.CNIC)

class Visitor(Person):
    pass

class Admin(Person):
    email = models.EmailField()

class Guard(Person):
    pass

class Host(Person):
    email = models.EmailField()

class Requests(models.Model):
    Pending = 'Pending'
    Approved = 'Approved'
    Denied = 'Denied'

    approvalChoices = (
        (Pending, 'Pending'),
        (Approved, 'Approved'),
        (Denied, 'Denied'),
    )

    hostID = models.ForeignKey(Host, on_delete=models.CASCADE)
    dateRequested = models.DateTimeField('Date Requested', auto_now_add=True)
    expectedArrivalDate = models.DateTimeField('Expected Arrival Date', null=True)
    approval = models.CharField(max_length=8, choices=approvalChoices, default=Pending)
    approvalTime = models.DateTimeField('Approval Time', null=True)
    numGuests = models.IntegerField(default=1)
    adminID = models.ForeignKey(Admin)

class Visit(models.Model):
    requestID = models.ForeignKey(Requests)
    visitDate = models.DateTimeField('Visit Date', auto_now_add=True)
    entryTime = models.DateTimeField('Entry Time', auto_now_add=True)
    exitTime = models.DateTimeField('Exit Time', null=True)


class GuestsPerVisit(models.Model):
    visitID = models.ForeignKey(Visit)
    visitorID = models.ForeignKey(Visitor)
    guardID = models.ForeignKey(Guard)

class RequestedGuests(models.Model):
    requestID = models.ForeignKey(Requests)
    visitorID = models.ForeignKey(Visitor)  