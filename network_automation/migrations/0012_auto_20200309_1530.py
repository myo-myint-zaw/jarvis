# Generated by Django 3.0.3 on 2020-03-09 07:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation', '0011_remove_auditlogs_email'),
    ]

    operations = [
        migrations.RenameField(
            model_name='auditlogs',
            old_name='username',
            new_name='user',
        ),
    ]
