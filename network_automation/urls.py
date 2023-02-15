from . import views
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path("", views.index, name="index"),
    path("invalid-user", views.invalid_user, name="invalid_user"),
    path("platform", views.platform, name="platform"),
    path("user_dashboard", views.user_dashboard, name="user_dashboard"),
    path("automation_modules", views.automation_modules, name="automation_modules"),
    path("download_template/<str:device_name>", views.download_template, name="download_template"),
    path("download_inventory/<str:device_name>", views.download_inventory, name="download_inventory"),
    path("aci", views.aci, name="aci"),
    path("aci_login", views.aci_login, name="aci_login"),
    path("aci_log", views.aci_log, name="aci_log"),
    path("f5", views.f5, name="f5"),
    path("f5_log", views.f5_log, name="f5_log"),
    path("ios", views.ios, name="ios"),
    path("ios_log", views.ios_log, name="ios_log"),
    path("viptela", views.viptela, name="viptela"),
    path("viptela_log", views.viptela_log, name="viptela_log"),
    path("ftd", views.ftd, name="ftd"),
    path("infoblox", views.infoblox, name="infoblox"),
    path("nx_os", views.nx_os, name="nx_os"),
    path("allot", views.allot, name="allot"),
    path("palo_alto", views.palo_alto, name="palo_alto"),
    path("mcafee_proxy", views.mcafee_proxy, name="mcafee_proxy"),
    path("algosec", views.algosec, name="algosec"),
    path("aeos", views.aeos, name="aeos"),
    path("logout", views.logout, name="logout"),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
