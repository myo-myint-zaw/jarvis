"""
Common dictionaries used in the Project
"""

groups_dict = {
    "aci_box": "acigroup",
    "f5_box": "f5group",
    "viptela_box": "viptelagroup",
    "ftd_box": "ftdgroup",
    "nxos_box": "nxosgroup",
    "infoblox_box": "infobloxgroup",
    "ios_box": "iosgroup",
    "allot_box": "allotgroup",
    "paloalto_box": "paloaltogroup",
    "proxy_box": "proxygroup",
    "algosec_box": "algosecgroup",
    "aeos_box": "aeosgroup",
}


download_devices = {
    "aci": {"template_name": "ACI_Deployment_Template.xlsx", "group_name": "acigroup"},
    "f5": {"template_name": "F5_Deployment_Template.xlsx", "group_name": "f5group"},
    "sdwan": {"template_name": "SDWAN_Deployment_Template.xlsx", "group_name": "viptelagroup"},
    "ios": {
        "group_name": "iosgroup",
        "template_name": "IOS_Deployment_Template.xlsx",
        "inventory_file": "IOS_Inventory.yml",
    }
}
