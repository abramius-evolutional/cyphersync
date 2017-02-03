from django.db import models
from datetime import datetime
from django.utils.timezone import utc
from django.template.loader import render_to_string
from django.conf import settings
from django.core.mail import send_mail
import uuid


class AccessToken(models.Model):
    token = models.CharField(max_length=36, unique=True)
    dt_initialization = models.DateTimeField(default=datetime.now().replace(tzinfo=utc))
    dt_expiration = models.DateTimeField()
    user = models.ForeignKey('person.Person', related_name='access_tokens')
    device = models.ForeignKey('person.Device', related_name="access_tokens")
    details = models.TextField(blank=True, default='')
    def __unicode__(self):
        return self.user.__unicode__() + ' / ' + self.token
    @classmethod
    def access(cls, token):
        try:
            accessToken = AccessToken.objects.get(token=token, dt_expiration__gte=datetime.now())
        except:
            accessToken = None

        if accessToken is None:
            return None
        else:
            return accessToken.user
    @classmethod
    def getAccessToken(cls, token):
        try:
            accessToken = AccessToken.objects.get(token=token, dt_expiration__gte=datetime.now())
        except:
            accessToken = None
        return accessToken

class ConfirmationToken(models.Model):
    token = models.CharField(max_length=36, unique=True)
    dt_initialization = models.DateTimeField(default=datetime.now().replace(tzinfo=utc))
    dt_expiration = models.DateTimeField()
    user = models.ForeignKey('person.Person', related_name='confirmation_tockens')
    def __unicode__(self):
        return self.user.__unicode__() + ' / ' + self.token
    def sendmail(self):
        name = ''
        if name=='':
            name = self.user.email
        confirm_url = '%s%s%s' % (settings.CURRENT_GENERAL_HOST, 'auth/confirm_email/', self.token)
        textbody = render_to_string('confirm_email.template', {
                'username': name,
                'confirm_url': confirm_url
            })
        textsubject = render_to_string('confirm_email_subject.template', {
                'username': name
            })

        send_mail(textsubject,
            textbody,
            settings.EMAIL_HOST_USER,
            [self.user.email],
            fail_silently=False)

class ChangePasswordToken(models.Model):
    token = models.CharField(max_length=36, unique=True)
    dt_initialization = models.DateTimeField(default=datetime.now().replace(tzinfo=utc))
    dt_expiration = models.DateTimeField()
    user = models.ForeignKey('person.Person', related_name='change_password_tokens')
    def __unicode__(self):
        return self.user.__unicode__() + ' / ' + self.token
    def sendmail(self):
        name = ''
        if name=='':
            name = self.user.email
        confirm_url = '%s%s%s' % (settings.CURRENT_GENERAL_HOST, 'auth/change_password/', self.token)
        textbody = render_to_string('change_password.template', {
            'username': name,
            'confirm_url': confirm_url
        })
        textsubject = render_to_string('change_password_subject.template', {
            'username': name
        })

        send_mail(textsubject,
            textbody,
            settings.EMAIL_HOST_USER,
            [self.user.email],
            fail_silently=False)

