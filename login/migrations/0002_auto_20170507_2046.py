# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-07 20:46
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='visitor',
            old_name='firstName',
            new_name='first_name',
        ),
        migrations.RenameField(
            model_name='visitor',
            old_name='lastName',
            new_name='last_name',
        ),
    ]
