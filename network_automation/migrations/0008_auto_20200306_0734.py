# Generated by Django 3.0.3 on 2020-03-06 07:34

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation', '0007_auditlogs'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='auditlogs',
            name='time',
        ),
        migrations.AddField(
            model_name='auditlogs',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2020, 3, 6, 7, 34, 47, 364797, tzinfo=utc), editable=False),
        ),
    ]
