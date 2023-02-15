import json

from .models import AuditLogs
from .common_dicts import download_devices
from .common import prepare_gui_freeze_boxes
from .device_manager import AciManager, F5Manager, IOSManager, vManageManager
from .forms import LoginForm, ACIMenuForm, F5MenuForm, IOSMenuForm, SDWANMenuForm


from django.conf import settings
from django.core import serializers
from django.utils.timezone import localtime
from django.shortcuts import render, redirect
from django.http import FileResponse, HttpResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required


def index(request):
    form = LoginForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return platform(request)
            else:
                return invalid_user(request)
        else:
            return invalid_user(request)
    return render(request, "index.html")


def invalid_user(request):
    return render(request, "html/invalid-user.html")


@login_required(login_url="/")
def platform(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if "admingroup" in user_groups:
        display_user_management = "yes"
    else:
        display_user_management = "no"
    return render(request, "html/platform.html", {"display_user_management": display_user_management})


@login_required(login_url="/")
def user_dashboard(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if "admingroup" in user_groups:
        audit_logs = serializers.serialize("json", AuditLogs.objects.all().order_by("-date", "-time"))
    else:
        audit_logs = serializers.serialize(
            "json", AuditLogs.objects.all().filter(user=request.user).order_by("-date", "-time")
        )
    return render(request, "html/user_dashboard.html", {"audit_logs": audit_logs})


@login_required(login_url="/")
def automation_modules(request):
    user_groups = [i.name for i in request.user.groups.all()]
    return render(request, "html/automation_modules.html", {"freeze": prepare_gui_freeze_boxes(user_groups)})


@login_required(login_url="/")
def download_template(request, device_name):
    user_groups = [i.name for i in request.user.groups.all()]
    if (download_devices[device_name]["group_name"] in user_groups) or ("admingroup" in user_groups):
        file_content = settings.MEDIA_ROOT + f"/spreadsheets/{download_devices[device_name]['template_name']}"
        spreadsheet = open(file_content, "rb")
        return FileResponse(spreadsheet)
    else:
        return automation_modules(request)


@login_required(login_url="/")
def download_inventory(request, device_name):
    user_groups = [i.name for i in request.user.groups.all()]
    if (download_devices[device_name]["group_name"] in user_groups) or ("admingroup" in user_groups):
        file_content = settings.MEDIA_ROOT + f"/inventory/{download_devices[device_name]['inventory_file']}"
        spreadsheet = open(file_content, "rb")
        return FileResponse(spreadsheet)
    else:
        return automation_modules(request)


@login_required(login_url="/")
def aci(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("acigroup" in user_groups) or ("admingroup" in user_groups):
        if request.method == "POST":
            form = ACIMenuForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES["uploaded_file"]
                audit_logger = AuditLogs(
                    user=str(request.user),
                    date=localtime().date(),
                    time=localtime().time().strftime("%I:%M %p"),
                    template_name=uploaded_file.name,
                    action=form.cleaned_data.get("menu_option"),
                )
                host_ip = form.cleaned_data.get("host_ip")
                aci_username = form.cleaned_data.get("aci_username")
                aci_password = form.cleaned_data.get("aci_password")
                device_runner = AciManager({"host_ip": host_ip, "username": aci_username, "password": aci_password})
                device_runner.inventory_setup(spreadsheet_path=uploaded_file.temporary_file_path())
                result, output = device_runner.run_ansible(action=audit_logger.action)
                result = "PASS" if result else "FAIL"
                audit_logger.result = result
                audit_logger.save()
                return render(request, "html/aci.html", {"output": output})
        return render(request, "html/aci.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def aci_login(request):
    if request.method == "POST" and request.is_ajax():
        ajax_data = json.loads(request.body)
        host_ip = ajax_data.get("host_ip", None)
        username = ajax_data.get("username", None)
        password = ajax_data.get("password", None)
        if host_ip and username and password:
            device_runner = AciManager({"host_ip": host_ip, "username": username, "password": password})
            return HttpResponse(device_runner.aci_login())
    return aci(request)


@login_required(login_url="/")
def aci_log(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("acigroup" in user_groups) or ("admingroup" in user_groups):
        return FileResponse(open("/var/log/jarvis/aci_runs.log", "rb"))
    else:
        return aci(request)


@login_required(login_url="/")
def f5(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("f5group" in user_groups) or ("admingroup" in user_groups):
        if request.method == "POST":
            form = F5MenuForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES["uploaded_file"]
                audit_logger = AuditLogs(
                    user=str(request.user),
                    date=localtime().date(),
                    time=localtime().time().strftime("%I:%M %p"),
                    template_name=uploaded_file.name,
                    action=form.cleaned_data.get("menu_option"),
                )
                f5_username = form.cleaned_data.get("f5_username")
                f5_password = form.cleaned_data.get("f5_password")
                device_runner = F5Manager({"username": f5_username, "password": f5_password})
                device_runner.inventory_setup(spreadsheet_path=uploaded_file.temporary_file_path())
                result, output = device_runner.run_ansible(action=audit_logger.action)
                result = "PASS" if result else "FAIL"
                audit_logger.result = result
                audit_logger.save()
                return render(request, "html/f5.html", {"output": output})
        return render(request, "html/f5.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def f5_log(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("f5group" in user_groups) or ("admingroup" in user_groups):
        return FileResponse(open("/var/log/jarvis/f5_runs.log", "rb"))
    else:
        return f5(request)


@login_required(login_url="/")
def ios(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("iosgroup" in user_groups) or ("admingroup" in user_groups):
        if request.method == "POST":
            form = IOSMenuForm(request.POST, request.FILES)
            if form.is_valid():
                deployment_file = request.FILES["deployment_file"]
                inventory_file = request.FILES["inventory_file"]
                audit_logger = AuditLogs(
                    user=str(request.user),
                    date=localtime().date(),
                    time=localtime().time().strftime("%I:%M %p"),
                    template_name=deployment_file.name,
                    action=form.cleaned_data.get("menu_option"),
                )
                device_runner = IOSManager()
                device_runner.inventory_setup(
                    spreadsheet_path=deployment_file.temporary_file_path(),
                    inventory_path=inventory_file.temporary_file_path()
                )
                result, output = device_runner.run_ansible(action=audit_logger.action)
                result = "PASS" if result else "FAIL"
                audit_logger.result = result
                audit_logger.save()
                return render(request, "html/ios.html", {"output": output})
        return render(request, "html/ios.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def ios_log(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("iosgroup" in user_groups) or ("admingroup" in user_groups):
        return FileResponse(open("/var/log/jarvis/ios_runs.log", "rb"))
    else:
        return ios(request)

@login_required(login_url="/")
def viptela(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("viptelagroup" in user_groups) or ("admingroup" in user_groups):
        if request.method == "POST":
            form = SDWANMenuForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES["uploaded_file"]
                audit_logger = AuditLogs(
                    user=str(request.user),
                    date=localtime().date(),
                    time=localtime().time().strftime("%I:%M %p"),
                    template_name=uploaded_file.name,
                    action=form.cleaned_data.get("menu_option"),
                )
                host_ip = form.cleaned_data.get("host_ip")
                vmanage_username = form.cleaned_data.get("vmanage_username")
                vmanage_password = form.cleaned_data.get("vmanage_password")
                device_runner = vManageManager({"host_ip": host_ip, "username": vmanage_username, "password": vmanage_password})
                device_runner.inventory_setup(spreadsheet_path=uploaded_file.temporary_file_path())
                result, output = device_runner.run_ansible(action=audit_logger.action)
                result = "PASS" if result else "FAIL"
                audit_logger.result = result
                audit_logger.save()
                return render(request, "html/viptela.html", {"output": output})
        return render(request, "html/viptela.html")
    else:
        return automation_modules(request)

@login_required(login_url="/")
def viptela_log(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("viptelagroup" in user_groups) or ("admingroup" in user_groups):
        return FileResponse(open("/var/log/jarvis/viptela_runs.log", "rb"))
    else:
        return viptela(request)


@login_required(login_url="/")
def ftd(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("ftdgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/ftd.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def infoblox(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("infobloxgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/infoblox.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def nx_os(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("nxosgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/nx_os.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def allot(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("allotgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/allot.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def palo_alto(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("paloaltogroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/palo_alto.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def mcafee_proxy(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("proxygroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/mcafee_proxy.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def algosec(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("algosecgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/algosec.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def aeos(request):
    user_groups = [i.name for i in request.user.groups.all()]
    if ("aeosgroup" in user_groups) or ("admingroup" in user_groups):
        return render(request, "html/aeos.html")
    else:
        return automation_modules(request)


@login_required(login_url="/")
def logout(request):
    django_logout(request)
    return redirect("/")
