import os


from django.db import models
from django.conf import settings
from django.utils.timezone import now
from django.core.files.storage import FileSystemStorage


class OverwriteStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            os.remove(os.path.join(settings.MEDIA_ROOT, name))
        return name


class InventoryFile(models.Model):
    class Meta:
        verbose_name_plural = "Inventory Files"

    inventory_Name = models.CharField(max_length=300)
    inventory_File = models.FileField(upload_to="inventory/", storage=OverwriteStorage())

    def __str__(self):
        return self.inventory_Name


class DeviceTemplate(models.Model):
    class Meta:
        verbose_name_plural = "Device Templates"

    template_Name = models.CharField(max_length=300)
    template_File = models.FileField(upload_to="spreadsheets/", storage=OverwriteStorage())

    def __str__(self):
        return self.template_Name


class AuditLogs(models.Model):
    class Meta:
        verbose_name_plural = "Audit Logs"

    user = models.CharField(max_length=100)
    template_name = models.CharField(max_length=150)
    action = models.CharField(max_length=100)
    date = models.DateField(default=now().date())
    time = models.TimeField(default=now().time().strftime("%I:%M %p"))
    result = models.CharField(max_length=10)

    def __str__(self):
        return self.user
