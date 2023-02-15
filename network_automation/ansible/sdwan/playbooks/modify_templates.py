"""
Author: Myo Myint Zaw
Purpose: Spreadsheet parser, converts Engineering data to JSON payload to be used in REST calls.
Date: 8-Jul-2020
"""

import sys
import json
import pandas as pd
import numpy as np
from device_mapping import deviceType, deviceModel
from template_blueprints import *


# Global
new_dict = {
        "deviceType": [],
        "factoryDefault": "false",
        "templateDefinition": '',
        "templateDescription": "ISRv-OSPF",
        "templateMinVersion": "15.0.0",
        "templateName": "ISRv-OSPF",
        "templateType": "ospf"
    }

class Templates:
    """ Cisco SDWAN Feature Templates """
    def __init__(self, conf_file):
        self.config_file = conf_file

    def create_bfd_templates(self, bfd):
        """ Creating BFD Feature Templates Payload """
        bfd = bfd.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_bfd = []
        name, description, device_type = None, None, None
        for i in bfd.values:
            device_type, device_model = ([] for _ in range(2))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                for j in display_name:
                    device_mol = {
                        "name": deviceModel.get(j),
                        "displayName": j,
                        "deviceType": deviceType.get(j),
                        "isCliSupported": False,
                        "isCiscoDeviceModel": True
                    }
                    device_model.append(device_mol)
                    device_type.append(deviceModel.get(j))
                list_of_bfd.append(BfdTemplate(name, description, device_type, device_model,
                int(i[3]), int(i[4]), i[5], int(i[6]), int(i[7]), i[8]).to_json())
        return list_of_bfd


    def process_spreadsheet(self, sheetname):
        """ Processing spreadsheet data """
        viptela_spreadsheet = pd.read_excel(self.config_file, sheet_name=None)
        actions = {
            "AAA": "self.create_aaa_templates(viptela_spreadsheet['AAA'])",
            "BFD": "self.create_bfd_templates(viptela_spreadsheet['BFD'])",
            "NTP": "self.create_ntp_templates(viptela_spreadsheet['NTP'])",
            "OMP": "self.create_omp_templates(viptela_spreadsheet['OMP'])",
            "Security": "self.create_security_templates(viptela_spreadsheet['Security'])",
            "VPN0_512": "self.create_vpn0_templates(viptela_spreadsheet['VPN0_512'])",
            "VPN_Others": "self.create_vpn_others_templates(viptela_spreadsheet['VPN_Others'])",
            "VPN_Int_Ethernet": "self.create_vpn_ethernet_templates(viptela_spreadsheet['VPN_Int_Ethernet'])",
            "Banner": "self.create_banner_templates(viptela_spreadsheet['Banner'])",
            "Logging": "self.create_logging_templates(viptela_spreadsheet['Logging'])",
            "OSPF": "self.create_ospf_templates(viptela_spreadsheet['OSPF'])",
            "SNMPv2": "self.create_snmpv2_templates(viptela_spreadsheet['SNMPv2'])",
            "SNMPv3": "self.create_snmpv3_templates(viptela_spreadsheet['SNMPv3'])",
        }
        for k,v in actions.items():
            if k == sheetname:
                return eval(v)


conf_file = sys.argv[1]
sheetname = sys.argv[2]
json_file = "./templates/" + sheetname.lower() + "_data.json"

data = Templates(conf_file)
data = data.process_spreadsheet(sheetname)
data = json.dumps(data, indent=4)

if data != "null":
    with open(json_file, "w") as f:
        f.write(data)
