"""
Author: Myo Myint Zaw
Purpose: Spreadsheet parser, converts Engineering data to JSON payload to be used in REST calls.
Date: 8-Jul-2020
"""
import re
import sys
import json
import pandas as pd
import numpy as np
from device_mapping import deviceType, deviceModel
from template_blueprints import *

# Global
#vDir = "D:\\_DATA\\SourceCode\\python\\sdwan\\templates\\"
vDir = "./templates/"

# vipType = {"Global": "constant", "Device Specific": "variableName"}
vipType = "constant"
dataConvert = {"On": "true", "Off": "false"}
toDelete = ["attachedMastersCount", "configType", "createdBy", "createdOn", "devicesAttached", "lastUpdatedBy", "lastUpdatedOn", "resourceGroup"]

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


    def create_aaa_templates(self, aaa):
        """ Creating AAA Feature Templates Payload """
        aaa = aaa.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_aaa = []
        name, description, device_type = None, None, None
        for i in aaa.values:
            device_type, device_model, aaa_user, tacacs_servers = ([] for _ in range(4))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                auth_order = i[3].split(",")
                tacacs_server, priority, secret_key = i[8].split(","), i[9].split(","), i[12].split(",")
                username, u_description, password, group = i[13].split(","), i[14].split(","), i[15].split(","), i[16].split(",")
                for j, k, l in zip(tacacs_server,priority,secret_key):
                    tacacs_servers.append(
                        AaaTacacs(
                            j, i[10], int(i[11]), int(k), l
                        ).to_json()
                    )
                for j, k, l , m in zip(username,u_description,password,group):
                    aaa_user.append(
                        AaaUser(
                            j, k, l, m
                        ).to_json()
                    )
                for l in display_name:
                    device_mol = {
                        "name": deviceModel.get(l),
                        "displayName": l,
                        "deviceType": deviceType.get(l),
                        "isCliSupported": False,
                        "isCiscoDeviceModel": True
                    }
                    device_model.append(device_mol)
                    device_type.append(deviceModel.get(l))
                list_of_aaa.append(AaaTemplate(name, description, device_type, device_model, auth_order[0], auth_order[1], auth_order[2],
                i[4], i[5], aaa_user, int(i[6]), i[7], tacacs_servers).to_json())
        return list_of_aaa


    def create_ntp_templates(self, ntp):
        """ Creating NTP Feature Templates Payload """
        ntp = ntp.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_ntp = []
        name, description, device_type = None, None, None
        for i in ntp.values:
            device_type, device_model, ntp_servers = ([] for _ in range(3))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                servers, preference = i[3].split(","), i[6].split(",")
                for j, k in zip(servers,preference):
                    ntp_servers.append(
                        NtpServers(
                            j, i[4], i[5], dataConvert.get(k)
                        ).to_json()
                    )
                for l in display_name:
                    device_mol = {
                        "name": deviceModel.get(l),
                        "displayName": l,
                        "deviceType": deviceType.get(l),
                        "isCliSupported": False,
                        "isCiscoDeviceModel": True
                    }
                    device_model.append(device_mol)
                    device_type.append(deviceModel.get(l))
                list_of_ntp.append(NtpTemplate(name, description, device_type, device_model, ntp_servers).to_json())
        return list_of_ntp


    def create_omp_templates(self, omp):
        """ Creating OMP Feature Templates Payload """
        omp = omp.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_omp = []
        name, description, device_type = None, None, None
        for i in omp.values:
            device_type, device_model, v4_advertise, v6_advertise = ([] for _ in range(4))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                # IPv4 Advertise
                v4_protocol = ['bgp', 'connected', 'static']
                v4 = 0
                for j in (7,9,10):
                    if i[j] == "On":
                        v4_advertise.extend(OmpIpv4(v4_protocol[v4]).to_json())
                    v4 += 1
                if i[8] == "On":
                    v4_advertise.append(OmpIpv4("ospf").to_json_ospf())

                # IPv6 Advertise
                v6_protocol = ['bgp', 'connected', 'static']
                v6 = 0
                for j in (11,12,13):
                    if i[j] == "On":
                        v6_advertise.append(OmpIpv6(v6_protocol[v6]).to_json())
                    v6 += 1

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

                list_of_omp.append(OmpTemplate(name, description, device_type, device_model, dataConvert.get(i[3]), i[4],
                i[5], i[6], v4_advertise, v6_advertise).to_json())

        return list_of_omp


    def create_security_templates(self, security):
        """ Creating Security Feature Templates Payload """
        security = security.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_security = []
        name, description, device_type = None, None, None
        for i in security.values:
            device_type, device_model, auth_types = ([] for _ in range(3))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                authentication_type = i[5].split(",")
                for j in authentication_type:
                    auth_types.append(j)
                for k in display_name:
                    device_mol = {
                        "name": deviceModel.get(k),
                        "displayName": k,
                        "deviceType": deviceType.get(k),
                        "isCliSupported": False,
                        "isCiscoDeviceModel": True
                    }
                    device_model.append(device_mol)
                    device_type.append(deviceModel.get(k))

                list_of_security.append(SecurityTemplate(name, description, device_type, device_model, i[3], i[4], auth_types).to_json())
        return list_of_security



    def create_vpn0_templates(self, vpn0):
        """ Creating VPN0 Feature Templates Payload """
        vpn0 = vpn0.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_vpn0 = []
        name, description, device_type = None, None, None
        for i in vpn0.values:
            device_type, device_model, dns_servers = ([] for _ in range(3))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                dns_servers_name = i[6].split(",")
                dns_roles = i[7].split(",")
                for k in display_name:
                    device_mol = {
                        "name": deviceModel.get(k),
                        "displayName": k,
                        "deviceType": deviceType.get(k),
                        "isCliSupported": False,
                        "isCiscoDeviceModel": True
                    }
                    device_model.append(device_mol)
                    device_type.append(deviceModel.get(k))

                for server, role in zip(dns_servers_name, dns_roles):
                    if server != "N.A":
                        dns_servers.append(Vpn0DnsServers(server,role).to_json())
                if dns_servers:
                    vipType = "constant"
                    list_of_vpn0.append(Vpn0Template(name, description, device_type, device_model, i[3], i[4], dataConvert.get(i[5]), 
                    dns_servers, i[8], i[9], vipType).to_json())
                else:
                    vipType = "ignore"
                    list_of_vpn0.append(Vpn0Template(name, description, device_type, device_model, i[3], i[4], dataConvert.get(i[5]), 
                    dns_servers, i[8], i[9], vipType).to_json())

        return list_of_vpn0


    def create_vpn_others_templates(self, vpn_others):
        """ Creating VPN Others Feature Templates Payload """
        vpn_others = vpn_others.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_vpn_others = []
        name = description = device_type = None
        for i in vpn_others.values:
            device_type, device_model, v4_advertise, v6_advertise = ([] for _ in range(4))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                # IPv4 Advertise
                v4_protocol = ['bgp', 'static', 'connected', 'eigrp', 'lisp', 'isis']
                v4 = 0
                for j in (6,7,8,10,11,12):
                    if i[j] == "On":
                        v4_advertise.extend(VpnOthersIpv4(v4_protocol[v4]).to_json())
                    v4 += 1
                if i[9] == "On":
                    v4_advertise.append(VpnOthersIpv4("ospf").to_json_ospf())

                # IPv6 Advertise
                v6_protocol = ['bgp', 'connected', 'static']
                v6 = 0
                for j in (13,14,15):
                    if i[j] == "On":
                        v6_advertise.append(VpnOthersIpv6(v6_protocol[v6]).to_json())
                    v6 += 1

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

                list_of_vpn_others.append(VpnOthersTemplate(name, description, device_type, device_model, i[3], i[4], dataConvert.get(i[5]),
                v4_advertise, v6_advertise).to_json())

        return list_of_vpn_others


    def create_vpn_ethernet_templates(self, vpn_ethernet):
        """ Creating VPN Interface Ethernet Feature Templates Payload """
        vpn_ethernet = vpn_ethernet.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_vpn_ethernet = []
        name, description, device_type = None, None, None
        for i in vpn_ethernet.values:
            device_type, device_model = [], []
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

                list_of_vpn_ethernet.append(VpnEthernetTemplate(name, description, device_type, device_model, i[3], i[4], i[5], i[6], i[7],
                i[8], i[9], dataConvert.get(i[10]), int(i[11]), dataConvert.get(i[12]), dataConvert.get(i[13]), dataConvert.get(i[14]), dataConvert.get(i[15]), 
                dataConvert.get(i[16]), dataConvert.get(i[17]), dataConvert.get(i[18]), dataConvert.get(i[19]), dataConvert.get(i[20]), dataConvert.get(i[21]), 
                dataConvert.get(i[22])).to_json())

        return list_of_vpn_ethernet


    def create_banner_templates(self, banner):
        """ Creating Banner Feature Templates Payload """
        banner = banner.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_banner = []
        name, description, device_type = None, None, None
        for i in banner.values:
            device_type, device_model = [], []
            #if i[0]:  #Original
            if i[0] != "" :
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

                list_of_banner.append(BannerTemplate(name, description, device_type, device_model, i[3], i[4]).to_json())

        return list_of_banner


    def create_logging_templates(self, logging):
        """ Creating Logging Feature Templates Payload """
        logging = logging.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_logging = []
        name, description, device_type = None, None, None
        for i in logging.values:
            device_type, device_model, logging_servers = ([] for _ in range(3))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                servers, vpn, src_int, priority = i[3].split(","), i[4].split(","), i[5].split(","), i[6].split(",")
                for j, k, l, m in zip(servers, vpn, src_int, priority):
                    logging_servers.append(
                        LoggingServersIpv4(
                            j, k, l, m
                        ).to_json()
                    )

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

                list_of_logging.append(LoggingTemplate(name, description, device_type, device_model, logging_servers).to_json())

        return list_of_logging


    def create_ospf_templates(self, ospf):
        """ Creating OSPF Feature Templates Payload """
        ospf = ospf.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_ospf = []
        name, description, device_type = None, None, None
        for i in ospf.values:
            device_type, device_model, ospf_redis = ([] for _ in range(3))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                # int, auth_key, md_id, md_key = i[5].split(","), i[7].split(","), i[8].split(","), i[9].split(",")
                # for j,k,l,m in zip(int, auth_key, md_id, md_key):
                #     ospf_int.append(OspfInterface(j,i[6],k,l,m).to_json())

                # OSPF Redistribute
                redis_protocol = ['static', 'connected', 'omp', 'bgp', 'eigrp', 'nat', 'natpool-outside']
                redis = 0
                for j in (10,11,12,13,14,15,16):
                    if i[j] == "On":
                        ospf_redis.append(OspfRedistribute(redis_protocol[redis]).to_json())
                    redis += 1

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

                list_of_ospf.append(OspfTemplate(name, description, device_type, device_model, i[3], ospf_redis).to_json())
        return list_of_ospf


    def create_snmpv2_templates(self, snmpv2):
        """ Creating SNMPv2 Feature Templates Payload """
        snmpv2 = snmpv2.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_snmpv2 = []
        name, description, device_type = None, None, None
        for i in snmpv2.values:
            device_type, device_model, trap_server, trap_module = ([] for _ in range(4))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                servers, vpn, port, src_int = i[9].split(","), i[10].split(","), i[11].split(","), i[12].split(",")
                for j, k, l, m in zip(servers, vpn, port, src_int):
                    trap_server.append(
                        TrapServer(
                            j, k, l, m, i[5], i[6]
                        ).to_json()
                    )
                
                severity = i[8].split(",")
                trap_module.append(TrapModule(i[7], severity).to_json())

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

                list_of_snmpv2.append(Snmpv2Template(name, description, device_type, device_model, i[3], i[4], i[5], i[6], trap_module, trap_server).to_json())

        return list_of_snmpv2


    def create_snmpv3_templates(self, snmpv3):
        """ Creating SNMPv3 Feature Templates Payload """
        snmpv3 = snmpv3.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_of_snmpv3 = []
        name, description, device_type = None, None, None
        for i in snmpv3.values:
            device_type, device_model, trap_server, trap_module, snmp_user = ([] for _ in range(5))
            if i[0]:
                name, description = i[0], i[1]
                display_name = i[2].split(",")
                servers, vpn, port, src_int = i[6].split(","), i[7].split(","), i[8].split(","), i[9].split(",")
                for j, k, l, m in zip(servers, vpn, port, src_int):
                    trap_server.append(
                        TrapServerV3(
                            j, k, l, m, i[3], i[14]
                        ).to_json()
                    )
                
                severity = i[5].split(",")
                trap_module.append(TrapModule(i[4], severity).to_json())

                user, auth_p, auth_pwd, privacy_p, privacy_pwd = i[14].split(","), i[15].split(","), i[16].split(","), i[17].split(","), i[18].split(",")
                for j, k, l, m, n in zip(user, auth_p, auth_pwd, privacy_p, privacy_pwd):
                    snmp_user.append(
                        SnmpUser(
                            j, k, l, m, n, i[12]
                        ).to_json()
                    )

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

                list_of_snmpv3.append(Snmpv3Template(name, description, device_type, device_model, i[3], i[10], i[11], i[12], i[13], snmp_user, trap_module, trap_server).to_json())

        return list_of_snmpv3



    # ---------------------------------------------------------------------------------------------------- #
    # Modifying Feature Templates
    def modify_ospf_templates(self, ospf):
        """ Modifying OSPF Feature Templates Payload """

        #ASA20211201 - New logic to modify OSPF Interface Template - BGN ----
        ospf = ospf.replace({np.nan: None})  # Replace all nan values to None in DataFrame
        list_dict = {}
        list_all = []

        for i in ospf.values:
            list = []
            if i[0]:
                for j in range(1,8):
                    list.append(i[j])
                list_all.append(list)

        for i, j in zip(ospf.values, list_all):
            if i[0]:
                if i[0] in list_dict:
                    list_dict[i[0]].append(j)
                else:
                    list_dict[i[0]] = []
                    list_dict[i[0]].append(j)

        #GetExistingTemplate - BGN ------
        with open("./templates/ospf_int_output.json") as f:
            f = json.loads(f.read())
        #GetExistingTemplate - END ------

        ospf_all = []
        cntloopx = 1
        vtx_namePrev = ""
        ospf_aream = ""
        ospf_int = []

        # Santi20211213-Check Existing Area Number and Get Existing Area Number -- BGN ----
        AreaNumDictPrev = ""
        # Santi20211213-Check Existing Area Number and Get Existing Area Number -- END ----

        for x in f:
            for l in toDelete:   del x[l]
            vt_name = x["templateName"]
            json_tmp = json.loads(x["templateDefinition"])
            x["templateDefinition"] = json_tmp

            for k, v in sorted(list_dict.items()):

                if vtx_namePrev != x["templateName"]:
                    cntloopx = 1
                    ospf_aream = ""

                if (x["templateName"].strip() == k.strip()):
                    ospf_aread = []
                    maxcntArea = len(v)
                    SortArea = sorted(v)

                    if (vtx_namePrev == vt_name):
                        # ASA20211214 - chk count different Area Number - BGN ----
                        cntANum = 1
                        for cntArea in range(maxcntArea):
                            AreaNumDict = SortArea[cntArea][0]
                            maxcntANum = 1

                            if (AreaNumDict != AreaNumDictPrev):
                                cntANum = 1

                            for cntAreaIn in range(maxcntArea):
                                AreaNumDictIn = SortArea[cntAreaIn][0]
                                if(AreaNumDict==AreaNumDictIn):
                                    maxcntANum = maxcntANum + 1
                                else:
                                    pass
                            if (maxcntANum>1): maxcntANum = maxcntANum - 1

                            # ASA20211214 - Logic create ospf detail based of the area number - BGN ---
                            AreaInt = SortArea[cntArea][1].split(',')
                            #Check authentication mode after sort -- BGN ----
                            if SortArea[cntArea][2] == "On":
                                auth, md5_key_id, md5_key = SortArea[cntArea][4].split(','), SortArea[cntArea][5].split(','), SortArea[cntArea][6].split(',')
                                for j, ink, l, m in zip(AreaInt, auth, md5_key_id, md5_key):
                                    ospf_int.append(OspfInterface(j, vipType, SortArea[cntArea][3], ink, int(l), m).to_json())
                            else:
                                for j in AreaInt:
                                    ospf_int.append(OspfInterface(j).to_json())
                            #Check authentication mode after sort -- END ----
                            # ASA20211214 - Logic create ospf detail based of the area number - END ---

                            # ASA20211214 - Logic create ospf based on the area number - BGN ---
                            if (cntANum==maxcntANum):
                                ospf_aread.append(OspfAreaANumD(AreaNumDict, ospf_int).to_json())
                                ospf_int = []

                            AreaNumDictPrev = AreaNumDict
                            cntANum = cntANum + 1
                            cntloopx = cntloopx + 1
                            # ASA20211214 - Logic create ospf based on the area number - END ---

                        # ASA20211214 - chk count different Area Number - END ----
                        if (cntloopx > 1): cntloopx = cntloopx - 1
                        if (cntloopx==maxcntArea):
                            if(ospf_aream == ""):
                                ospf_aream = OspfAreaANumM(ospf_aread).to_json()
                                x["templateDefinition"]["ospf"]["area"] = ospf_aream
                                ospf_all.append(x)

                    vtx_namePrev = vt_name

        return ospf_all


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
            "OSPF_Interface": "self.modify_ospf_templates(viptela_spreadsheet['OSPF_Interface'])",
            "SNMPv2": "self.create_snmpv2_templates(viptela_spreadsheet['SNMPv2'])",
            "SNMPv3": "self.create_snmpv3_templates(viptela_spreadsheet['SNMPv3'])"
        }
        for k,v in actions.items():
            if k == sheetname:
                return eval(v)


# def writeJson(jsData, jsFile, jst):
#     # ASA20211130 - add a-num loop - BGN ---
#     jsospf = vDir + jsFile

#     if (jst == "log"):
#         with open(jsospf, 'w') as f:
#             for listitem in jsData:
#                 f.write('%s\n' % listitem)

#     if (jst == "json"):
#         dtospf = json.dumps(jsData, indent=4)
#         if dtospf != "null":
#             with open(jsospf, 'w') as f:
#                 f.write(dtospf)

#     print("write "+ jst +" file - "+ jsFile +" - done -------------")
#     # ASA20211130 - add a-num loop - END ---


conf_file = sys.argv[1]
sheetname = sys.argv[2]

json_file = vDir + sheetname.lower() + "_data.json"
data = Templates(conf_file)
data = data.process_spreadsheet(sheetname)
data = json.dumps(data, indent=4)
if data != "null":
    with open(json_file, "w") as f:
        f.write(data)
