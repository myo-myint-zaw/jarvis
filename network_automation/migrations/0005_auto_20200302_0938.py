# Generated by Django 3.0.3 on 2020-03-02 09:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation', '0004_auto_20200302_0934'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicetemplate',
            name='template_File',
            field=models.FileField(upload_to='spreadsheets/'),
        ),
    ]
