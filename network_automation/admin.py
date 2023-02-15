from django.contrib import admin
from .models import DeviceTemplate, AuditLogs


admin.site.site_url = "/platform"


@admin.register(DeviceTemplate)
class DeviceTemplateAdmin(admin.ModelAdmin):
    list_display = ("template_Name", "template_File")


@admin.register(AuditLogs)
class AuditLogsAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "template_name", "date", "time", "result")
    ordering = ("-date", "-time")
    search_fields = ("user", "action", "template_name", "date", "time")
