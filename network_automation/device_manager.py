"""
Device managers to manage devices
"""
import os
import json
import logging
import jmespath
import pandas as pd
import acitoolkit.acitoolkit as ACI


from .common import generate_summary, get_query_result, flatten
from subprocess import run, PIPE


# Global
abs_path = os.path.dirname(os.path.abspath(__file__))


def get_logger(device):
    logger = logging.getLogger(__file__)
    logger.setLevel("DEBUG")
    debug_handler = logging.handlers.RotatingFileHandler(
        f"/var/log/jarvis/{device}_runs.log",
        maxBytes=500000000,  # 500 MB size
        backupCount=10
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter("%(asctime)s \n%(message)s\n\n"))
    logger.addHandler(debug_handler)
    return logger


class AciManager:
    def __init__(self, credentials=None):
        if not credentials:
            credentials = dict()
        self.host_ip = credentials["host_ip"]
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.inventory_location = None
        self.destination_spreadsheet_location = None
        self.aci_session = None
        self.playbooks = {}

    def aci_login(self):
        self.aci_session = ACI.Session(f"https://{self.host_ip}", self.username, self.password)
        resp = self.aci_session.login()
        if resp.ok:
            response = "success"
        else:
            response = "failed"
        return response

    def inventory_setup(self, spreadsheet_path):
        self.inventory_location = abs_path + "/ansible/aci/inventory"
        self.destination_spreadsheet_location = abs_path + "/ansible/aci/ACI_Deployment_Template.xlsx"
        run(["cp", spreadsheet_path, self.destination_spreadsheet_location], stdout=PIPE)
        self.playbooks = {
            "fabric_node": abs_path + "/ansible/aci/playbooks/fabric_node.yml",
            "aci_rest_pool": abs_path + "/ansible/aci/playbooks/aci_rest_pool.yml",
            "aci_rest_static_nodemgmt": abs_path + "/ansible/aci/playbooks/aci_rest_static_nodemgmt.yml",
            "switch_policy": abs_path + "/ansible/aci/playbooks/switch_policy.yml",
            "vpc_protection_gr": abs_path + "/ansible/aci/playbooks/vpc_protection_gr.yml",
            "vlan_aep_dom": abs_path + "/ansible/aci/playbooks/vlan_aep_dom.yml",
            "portchannel_policy": abs_path + "/ansible/aci/playbooks/portchannel_policy.yml",
            "lldp_policy": abs_path + "/ansible/aci/playbooks/lldp_policy.yml",
            "cdp_policy": abs_path + "/ansible/aci/playbooks/cdp_policy.yml",
            "l2_interface_policy": abs_path + "/ansible/aci/playbooks/l2_interface_policy.yml",
            "int_policy_group": abs_path + "/ansible/aci/playbooks/int_policy_group.yml",
            "activate_int_profile": abs_path + "/ansible/aci/playbooks/activate_int_profile.yml",
            "tenant": abs_path + "/ansible/aci/playbooks/tenant.yml",
            "vrf": abs_path + "/ansible/aci/playbooks/vrf.yml",
            "bd": abs_path + "/ansible/aci/playbooks/bd.yml",
            "ap": abs_path + "/ansible/aci/playbooks/ap.yml",
            "epg_contract": abs_path + "/ansible/aci/playbooks/epg_contract.yml",
            "interface_epg_binding": abs_path + "/ansible/aci/playbooks/interface_epg_binding.yml",
        }
        self.create_inventory()

    def create_inventory(self):
        with open(self.inventory_location, "w") as f:
            lines = ["[apic]", "\n" f"{self.host_ip} username={self.username} password={self.password}" "\n"]
            for line in lines:
                f.writelines(line)

    def run_playbook(self, playbook_name):
        output = run(["ansible-playbook", "-i", self.inventory_location, playbook_name, "-v"], stdout=PIPE)
        str_output = output.stdout.decode("utf-8")
        json_output = json.loads(str_output[46:].replace("\n", ""))
        ansible_logger = get_logger("aci")
        ansible_logger.debug(str_output[46:])
        return json.dumps(json_output, indent=4)

    # Configure Fabric Node
    def node_registration(self):
        str_output = self.run_playbook(self.playbooks["fabric_node"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Fabric_Node")
        fabric_names = [i for i, j in zip(fabric_worksheet["Policy_Name"], fabric_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["fabric_node"].replace("fabric_node", "query/fabric_node"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_fabrics = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(node in device_fabrics for node in fabric_names) if device_fabrics and fabric_names else False
        if results:
            fabric_names = set(fabric_names)  # Avoid Duplicates
            str_fabric_names = ", ".join(fabric_names) if len(fabric_names) > 1 else " ".join(fabric_names)
            summary = generate_summary(
                f"{str_fabric_names} Fabric node(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_fabrics = [node for node in fabric_names if node not in device_fabrics]
            str_failed_fabrics = ", ".join(failed_fabrics) if len(failed_fabrics) > 1 else " ".join(failed_fabrics)
            summary = generate_summary(
                f"{str_failed_fabrics} Fabric node(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_ip_address_pool(self):
        str_output = self.run_playbook(self.playbooks["aci_rest_pool"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Fabric_Node")
        inband_addr = [i for i, j in zip(fabric_worksheet["INB_IP"], fabric_worksheet["State"]) if j == "present"]
        outband_addr = [i for i, j in zip(fabric_worksheet["OOB_IP"], fabric_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["aci_rest_pool"].replace("aci_rest_pool", "query/aci_rest_pool"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_inband_addr = list(flatten(query_result["inband_addr"])) if isinstance(query_result, dict) else []
        device_outband_addr = list(flatten(query_result["outband_addr"])) if isinstance(query_result, dict) else []
        results_inband = (
            all(i == j for i, j in zip(inband_addr, device_inband_addr))
            if device_inband_addr and inband_addr
            else False
        )
        results_outband = (
            all(i == j for i, j in zip(outband_addr, device_outband_addr))
            if device_outband_addr and outband_addr
            else False
        )
        results = results_inband and results_outband
        if results:
            ip_addr = set(inband_addr) | set(outband_addr)  # Avoid Duplicates
            str_ip_addr = ", ".join(ip_addr) if len(ip_addr) > 1 else " ".join(ip_addr)
            summary = generate_summary(
                f"{str_ip_addr} IP Addresses Pool(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_inband_addr = [i for i, j in zip(inband_addr, device_inband_addr) if i != j]
            failed_outband_addr = [i for i, j in zip(outband_addr, device_outband_addr) if i != j]
            failed_ip_addr = set(failed_inband_addr) | set(failed_outband_addr)
            str_failed_ip_addr = ", ".join(failed_ip_addr) if len(failed_ip_addr) > 1 else " ".join(failed_ip_addr)
            summary = generate_summary(
                f"{str_failed_ip_addr} IP Addresses Pool(s) Fail to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_mgmt_node(self):
        str_output = self.run_playbook(self.playbooks["aci_rest_static_nodemgmt"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Fabric_Node")
        node_group_ips_oob = [
            "".join([i, "/", j])
            for i, j, k in zip(
                fabric_worksheet["OOB_IP"], fabric_worksheet["OOB_subnetmask"], fabric_worksheet["State"]
            )
            if k == "present"
        ]
        node_group_ips_inb = [
            "".join([i, "/", j])
            for i, j, k in zip(
                fabric_worksheet["INB_IP"], fabric_worksheet["INB_subnetmask"], fabric_worksheet["State"]
            )
            if k == "present"
        ]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(
                self.playbooks["aci_rest_static_nodemgmt"].replace(
                    "aci_rest_static_nodemgmt", "query/aci_rest_static_nodemgmt"
                )
            )
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_node_group_ips_oob = list(flatten(query_result["oob_addr"])) if isinstance(query_result, list) else []
        device_node_group_ips_inb = list(flatten(query_result["inb_addr"])) if isinstance(query_result, list) else []
        results_oob = (
            all(i == j for i, j in zip(node_group_ips_oob, device_node_group_ips_oob))
            if device_node_group_ips_oob and node_group_ips_oob
            else False
        )
        results_inb = (
            all(i == j for i, j in zip(node_group_ips_inb, device_node_group_ips_inb))
            if device_node_group_ips_inb and node_group_ips_inb
            else False
        )
        results = results_oob and results_inb
        if results:
            ip_addr = set(node_group_ips_oob) and set(node_group_ips_inb) # Avoid Duplicates
            str_ip_addr = ", ".join(ip_addr) if len(ip_addr) > 1 else " ".join(ip_addr)
            summary = generate_summary(
                f"{str_ip_addr} Node Group IP(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_ip_addr_oob = set([i for i, j in zip(node_group_ips_oob, device_node_group_ips_oob) if i != j])
            failed_ip_addr_inb = set([i for i, j in zip(node_group_ips_inb, device_node_group_ips_inb) if i != j])
            failed_ip_addr = set(failed_ip_addr_oob) and set(failed_ip_addr_inb)
            str_failed_ip_addr = (
                ", ".join(failed_ip_addr) if len(failed_ip_addr) > 1 else " ".join(failed_ip_addr)
            )
            summary = generate_summary(
                f"{str_failed_ip_addr} Node Group IP(s) Fail to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    # Configure Fabric Access Policies
    def configure_switch_policies(self):
        str_output = self.run_playbook(self.playbooks["switch_policy"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Switch_Policy")
        switch_profile_names = [
            i for i, j in zip(fabric_worksheet["Switch_Profile"], fabric_worksheet["State"]) if j == "present"
        ]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["switch_policy"].replace("switch_policy", "query/switch_policy"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_switch_profiles = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = (
            all(profile in device_switch_profiles for profile in switch_profile_names)
            if device_switch_profiles and switch_profile_names
            else False
        )
        if results:
            switch_profile_names = set(switch_profile_names)  # Avoid Duplicates
            str_switch_profile_names = (
                ", ".join(switch_profile_names) if len(switch_profile_names) > 1 else " ".join(switch_profile_names)
            )
            summary = generate_summary(
                f"{str_switch_profile_names} Switch Profile(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_profile_names = [
                profile for profile in switch_profile_names if profile not in device_switch_profiles
            ]
            str_failed_profile_names = (
                ", ".join(failed_profile_names) if len(failed_profile_names) > 1 else " ".join(failed_profile_names)
            )
            summary = generate_summary(
                f"{str_failed_profile_names} Switch Profile(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_switch_vpc(self):
        str_output = self.run_playbook(self.playbooks["vpc_protection_gr"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="vPC_Protection_Gr")
        vpc_names = [
            i
            for i, j in zip(fabric_worksheet["vPC_Explicit_Protection_Group"], fabric_worksheet["State"])
            if j == "present"
        ]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(
                self.playbooks["vpc_protection_gr"].replace("vpc_protection_gr", "query/vpc_protection_gr")
            )
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_vpcs = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(vpc in device_vpcs for vpc in vpc_names) if device_vpcs and vpc_names else False
        if results:
            vpc_names = set(vpc_names)  # Avoid Duplicates
            str_vpc_names = ", ".join(vpc_names) if len(vpc_names) > 1 else " ".join(vpc_names)
            summary = generate_summary(
                f"{str_vpc_names} vPC Switch Pair(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_vpc_names = [vpc for vpc in vpc_names if vpc not in device_vpcs]
            str_failed_vpc_names = (
                ", ".join(failed_vpc_names) if len(failed_vpc_names) > 1 else " ".join(failed_vpc_names)
            )
            summary = generate_summary(
                f"{str_failed_vpc_names} vPC Switch Pair(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_vpool_domains_aep(self):
        str_output = self.run_playbook(self.playbooks["vlan_aep_dom"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="VLAN_AEP_Dom")
        fabric_worksheet = fabric_worksheet.to_dict()
        length_entries = len(fabric_worksheet["Domain_Type"])
        vm = {"vlan": [], "domain": [], "aep": [], "vlan_range": []}
        non_vm = {"vlan": [], "domain": [], "aep": [], "vlan_range": []}
        for i in range(0, length_entries):
            if fabric_worksheet["State"][i] == "present":
                if fabric_worksheet["Domain_Type"][i] != "vmm":
                    non_vm["vlan"].append(fabric_worksheet["VLAN_Names"][i])
                    non_vm["domain"].append(fabric_worksheet["Domain"][i])
                    non_vm["aep"].append(fabric_worksheet["AEP"][i])
                    non_vm["vlan_range"].append(
                        f"[vlan-{fabric_worksheet['Start_VLAN'][i]}]-to-[vlan-{fabric_worksheet['End_VLAN'][i]}]"
                    )
                else:
                    vm["vlan"].append(fabric_worksheet["VLAN_Names"][i])
                    vm["domain"].append(fabric_worksheet["Domain"][i])
                    vm["aep"].append(fabric_worksheet["AEP"][i])
                    vm["vlan_range"].append(
                        f"[vlan-{fabric_worksheet['Start_VLAN'][i]}]-to-[vlan-{fabric_worksheet['End_VLAN'][i]}]"
                    )
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["vlan_aep_dom"].replace("vlan_aep_dom", "query/vlan_aep_dom"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        # VLAN Range
        device_vlan_range = []
        if query_result.get("vlan_range", None):
            device_vlan_range = flatten(query_result["vlan_range"])
        # Non VM Domain Type
        device_non_vm = {}
        if query_result.get("non_vm", {}).get("aep", None):
            device_non_vm = {"aep": flatten(query_result["non_vm"]["aep"])}
        if query_result.get("non_vm", {}).get("domain", None):
            device_non_vm.update({"domain": flatten(query_result["non_vm"]["domain"])})
        if query_result.get("non_vm", {}).get("vlan", None):
            device_non_vm.update({"vlan": flatten(flatten(query_result["non_vm"]["vlan"]))})
        results_non_vm_vlan = False
        failed_non_vm_vlan = []
        for i, j in zip(non_vm["vlan"], non_vm["vlan_range"]):
            for k in device_vlan_range:
                if i in k:
                    if j in k:
                        results_non_vm_vlan = True
                    else:
                        results_non_vm_vlan = False
                        failed_non_vm_vlan.append(i)
        results_non_vm_domain = (
            all(i in j for i, j in zip(non_vm["domain"], device_non_vm["domain"]))
            if device_non_vm["domain"] and non_vm["domain"]
            else False
        )
        results_non_vm_aep = (
            all(i and j in k for i, j, k in zip(non_vm["domain"], non_vm["aep"], device_non_vm["aep"]))
            if device_non_vm["aep"] and non_vm["aep"]
            else False
        )
        results_non_vm = results_non_vm_vlan and results_non_vm_domain and results_non_vm_aep

        # VM Domain Type
        device_vm = {}
        if query_result.get("vm", {}).get("aep", None):
            device_vm = {"aep": flatten(query_result["vm"]["aep"])}
        if query_result.get("vm", {}).get("domain", None):
            device_vm.update({"domain": flatten(query_result["vm"]["domain"])})
        if query_result.get("vm", {}).get("vlan", None):
            device_vm.update({"vlan": flatten(flatten(query_result["vm"]["vlan"]))})
        results_vm_vlan = False
        failed_vm_vlan = []
        for i, j in zip(vm["vlan"], vm["vlan_range"]):
            for k in device_vlan_range:
                if i in k:
                    if j in k:
                        results_vm_vlan = True
                    else:
                        results_vm_vlan = False
                        failed_vm_vlan.append(i)
        results_vm_domain = (
            all(i in j for i, j in zip(vm["domain"], device_vm["domain"]))
            if device_vm["domain"] and vm["domain"]
            else False
        )
        results_vm_aep = (
            all(i and j in k for i, j, k in zip(vm["domain"], vm["aep"], device_vm["aep"]))
            if device_vm["aep"] and vm["aep"]
            else False
        )
        results_vm = results_vm_vlan and results_vm_domain and results_vm_aep
        results = results_non_vm and results_vm
        if results:
            vlan_names = set(vm["vlan"]) | set(non_vm["vlan"])  # Avoid Duplicates
            domain_names = set(vm["domain"]) | set(non_vm["domain"])  # Avoid Duplicates
            aep_names = set(vm["aep"]) | set(non_vm["aep"])  # Avoid Duplicates
            str_vlan_names = ", ".join(vlan_names) if len(vlan_names) > 1 else " ".join(vlan_names)
            str_domain_names = ", ".join(domain_names) if len(domain_names) > 1 else " ".join(domain_names)
            str_aep_names = ", ".join(aep_names) if len(aep_names) > 1 else " ".join(aep_names)
            summary = generate_summary(
                f"{str_vlan_names} VLAN(s); {str_domain_names} Domain(s); {str_aep_names} AEP(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_vlan_names = set(failed_vm_vlan) | set(failed_non_vm_vlan)
            failed_domain_names = set(i for i, j in zip(vm["domain"], device_vm["domain"]) if i not in j) | set(
                i for i, j in zip(non_vm["domain"], device_non_vm["domain"]) if i not in j
            )
            failed_aep_names = set(
                j for i, j, k in zip(vm["domain"], vm["aep"], device_vm["aep"]) if i and j not in k
            ) | set(j for i, j, k in zip(non_vm["domain"], non_vm["aep"], device_non_vm["aep"]) if i and j not in k)
            str_failed_vlan_names = (
                ", ".join(failed_vlan_names) if len(failed_vlan_names) > 1 else " ".join(failed_vlan_names)
            )
            str_failed_domain_names = (
                ", ".join(failed_domain_names) if len(failed_domain_names) > 1 else " ".join(failed_domain_names)
            )
            str_failed_aep_names = (
                ", ".join(failed_aep_names) if len(failed_aep_names) > 1 else " ".join(failed_aep_names)
            )
            summary = generate_summary(
                f"{str_failed_vlan_names} VLAN(s); {str_failed_domain_names} Domain(s); {str_failed_aep_names} AEP(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_lacp(self):
        str_output = self.run_playbook(self.playbooks["portchannel_policy"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="PortChannel_Policy")
        lacp_names = fabric_worksheet["LACP_Policy"].to_list()
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(
                self.playbooks["portchannel_policy"].replace("portchannel_policy", "query/portchannel_policy")
            )
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_lacps = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(lacp in device_lacps for lacp in lacp_names) if device_lacps else False
        if results:
            lacp_names = set(lacp_names)  # Avoid Duplicates
            str_lacp_names = ", ".join(lacp_names) if len(lacp_names) > 1 else " ".join(lacp_names)
            summary = generate_summary(
                f"{str_lacp_names} LACP Policy/Policies Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_lacps = [lacp for lacp in lacp_names if lacp not in device_lacps]
            str_failed_lacps = ", ".join(failed_lacps) if len(failed_lacps) > 1 else " ".join(failed_lacps)
            summary = generate_summary(
                f"{str_failed_lacps} LACP Policy/Policies Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary, str_output

    def configure_lldp(self):
        str_output = self.run_playbook(self.playbooks["lldp_policy"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="LLDP_Policy")
        lldp_names = fabric_worksheet["LLDP_Policy"].to_list()
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["lldp_policy"].replace("lldp_policy", "query/lldp_policy"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_lldps = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(lldp in device_lldps for lldp in lldp_names) if device_lldps else False
        if results:
            lldp_names = set(lldp_names)  # Avoid Duplicates
            str_lldp_names = ", ".join(lldp_names) if len(lldp_names) > 1 else " ".join(lldp_names)
            summary = generate_summary(
                f"{str_lldp_names} LLDP Policy/Policies Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_lldps = [lldp for lldp in lldp_names if lldp not in device_lldps]
            str_failed_lldps = ", ".join(failed_lldps) if len(failed_lldps) > 1 else " ".join(failed_lldps)
            summary = generate_summary(
                f"{str_failed_lldps} LLDP Policy/Policies Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary, str_output

    def configure_cdp(self):
        str_output = self.run_playbook(self.playbooks["cdp_policy"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="CDP_Policy")
        cdp_names = fabric_worksheet["CDP_Policy"].to_list()
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["cdp_policy"].replace("cdp_policy", "query/cdp_policy"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_cdps = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(cdp in device_cdps for cdp in cdp_names) if device_cdps else False
        if results:
            cdp_names = set(cdp_names)  # Avoid Duplicates
            str_cdp_names = ", ".join(cdp_names) if len(cdp_names) > 1 else " ".join(cdp_names)
            summary = generate_summary(
                f"{str_cdp_names} CDP Policy/Policies Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_cdps = [cdp for cdp in cdp_names if cdp not in device_cdps]
            str_failed_cdps = ", ".join(failed_cdps) if len(failed_cdps) > 1 else " ".join(failed_cdps)
            summary = generate_summary(
                f"{str_failed_cdps} CDP Policy/Policies Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary, str_output

#    def configure_l2(self):
#        str_output = self.run_playbook(self.playbooks["l2_interface_policy"])
#        # From Spreadsheet
#        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="L2_Interface_Policy")
#        l2_names = fabric_worksheet["L2_Interface"].to_list()
#        # From ACI Device
#        query_output = json.loads(
#            self.run_playbook(
#                self.playbooks["l2_interface_policy"].replace("l2_interface_policy", "query/l2_interface_policy")
#            )
#        )
#        query_result = get_query_result(query_output, self.host_ip)
#        device_l2s = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
#        results = all(l2 in device_l2s for l2 in l2_names) if device_l2s else False
#        if results:
#            l2_names = set(l2_names)  # Avoid Duplicates
#            str_l2_names = ", ".join(l2_names) if len(l2_names) > 1 else " ".join(l2_names)
#            summary = generate_summary(
#                f"{str_l2_names} L2 Policy/Policies Successfully configured on Cisco ACI {self.host_ip}\n"
#            )
#        else:
#            failed_l2s = [l2 for l2 in l2_names if l2 not in device_l2s]
#            str_failed_l2s = ", ".join(failed_l2s) if len(failed_l2s) > 1 else " ".join(failed_l2s)
#            summary = generate_summary(
#                f"{str_failed_l2s} L2 Policy/Policies Failed to configure on Cisco ACI {self.host_ip}\n"
#            )
#        return results, summary, str_output

    def configure_layer2_policies(self):
        results1, summary1, str_output1 = self.configure_lacp()
        results2, summary2, str_output2 = self.configure_lldp()
#        results3, summary3, str_output3 = self.configure_l2()
        results3, summary3, str_output3 = self.configure_cdp()
        summary = summary1 + "\n" + summary2 + "\n" + summary3
        str_output = str_output1 + "\n" + str_output2 + "\n" + str_output3
        return all([results1, results2, results3]), summary + str_output

    def configure_interface_policy_group(self):
        str_output = self.run_playbook(self.playbooks["int_policy_group"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Int_Policy_Group")
        inf_policy_groups = [
            i for i, j in zip(fabric_worksheet["Interface_Policy_Group"], fabric_worksheet["State"]) if j == "present"
        ]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["int_policy_group"].replace("int_policy_group", "query/int_policy_group"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_inf_policy_groups = (
            list(flatten(flatten(query_result.values()))) if isinstance(query_result, dict) else []
        )
        results = (
            all(inf in device_inf_policy_groups for inf in inf_policy_groups)
            if device_inf_policy_groups and inf_policy_groups
            else False
        )
        if results:
            inf_policy_groups = set(inf_policy_groups)  # Avoid Duplicates
            str_inf_policy_groups = (
                ", ".join(inf_policy_groups) if len(inf_policy_groups) > 1 else " ".join(inf_policy_groups)
            )
            summary = generate_summary(
                f"{str_inf_policy_groups} Interface Policy Group(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_inf_policy_groups = [intf for intf in inf_policy_groups if intf not in device_inf_policy_groups]
            str_failed_inf_policy_groups = (
                ", ".join(failed_inf_policy_groups)
                if len(failed_inf_policy_groups) > 1
                else " ".join(failed_inf_policy_groups)
            )
            summary = generate_summary(
                f"{str_failed_inf_policy_groups} Interface Policy Group(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def activate_switch_ports(self):
        str_output = self.run_playbook(self.playbooks["activate_int_profile"])
        # From Spreadsheet
        fabric_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Activate_Int_Profile")
        interface_names = [
            i for i, j in zip(fabric_worksheet["Interface_Profile"], fabric_worksheet["State"]) if j == "present"
        ]
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(
                self.playbooks["activate_int_profile"].replace("activate_int_profile", "query/activate_int_profile")
            )
        )
        query_result = get_query_result(query_output, self.host_ip)
        device_interfaces = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = (
            all(i in j for i, j in zip(interface_names, device_interfaces))
            if device_interfaces and interface_names
            else False
        )
        if results:
            interface_names = set(interface_names)  # Avoid Duplicates
            str_interface_names = ", ".join(interface_names) if len(interface_names) > 1 else " ".join(interface_names)
            summary = generate_summary(
                f"{str_interface_names} Interface Profile(s) Successfully activated on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_interfaces = [intf for intf in interface_names if intf not in device_interfaces]
            str_failed_interfaces = (
                ", ".join(failed_interfaces) if len(failed_interfaces) > 1 else " ".join(failed_interfaces)
            )
            summary = generate_summary(
                f"{str_failed_interfaces} Interface Profile(s) Failed to activate on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    # Configure Tenant Policies
    def configure_tenants(self):
        str_output = self.run_playbook(self.playbooks["tenant"])
        # From Spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Tenant_AP_EPG")
        tenant_names = [i for i, j in zip(tenant_worksheet["Tenant"], tenant_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(self.run_playbook(self.playbooks["tenant"].replace("tenant", "query/tenant")))
        query_result = get_query_result(query_output, self.host_ip)
        device_tenants = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(tenant in device_tenants for tenant in tenant_names) if device_tenants and tenant_names else False
        if results:
            tenant_names = set(tenant_names)  # Avoid Duplicates
            str_tenant_names = ", ".join(tenant_names) if len(tenant_names) > 1 else " ".join(tenant_names)
            summary = generate_summary(
                f"{str_tenant_names} tenant(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_tenants = [tenant for tenant in tenant_names if tenant not in device_tenants]
            str_failed_tenants = ", ".join(failed_tenants) if len(failed_tenants) > 1 else " ".join(failed_tenants)
            summary = generate_summary(
                f"{str_failed_tenants} tenant(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_vrf_tenants(self):
        str_output = self.run_playbook(self.playbooks["vrf"])
        # From Spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Tenant_AP_EPG")
        vrf_names = [i for i, j in zip(tenant_worksheet["VRF"], tenant_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(self.run_playbook(self.playbooks["vrf"].replace("vrf", "query/vrf")))
        query_result = get_query_result(query_output, self.host_ip)
        device_vrfs = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(vrf in device_vrfs for vrf in vrf_names) if device_vrfs and vrf_names else False
        if results:
            vrf_names = set(vrf_names)  # Avoid Duplicates
            str_vrf_names = ", ".join(vrf_names) if len(vrf_names) > 1 else " ".join(vrf_names)
            summary = generate_summary(f"{str_vrf_names} VRF(s) Successfully configured on Cisco ACI {self.host_ip}\n")
        else:
            failed_vrfs = [vrf for vrf in vrf_names if vrf not in device_vrfs]
            str_failed_vrfs = ", ".join(failed_vrfs) if len(failed_vrfs) > 1 else " ".join(failed_vrfs)
            summary = generate_summary(f"{str_failed_vrfs} VRF(s) Failed to configure on Cisco ACI {self.host_ip}\n")
        return results, summary + str_output

    def configure_bds_tenants(self):
        str_output = self.run_playbook(self.playbooks["bd"])
        # From Spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Tenant_AP_EPG")
        bd_names = [i for i, j in zip(tenant_worksheet["BD"], tenant_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(self.run_playbook(self.playbooks["bd"].replace("bd", "query/bd")))
        query_result = get_query_result(query_output, self.host_ip)
        device_bds = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(bd in device_bds for bd in bd_names) if device_bds and bd_names else False
        if results:
            bd_names = set(bd_names)  # Avoid Duplicates
            str_bd_names = ", ".join(bd_names) if len(bd_names) > 1 else " ".join(bd_names)
            summary = generate_summary(
                f"{str_bd_names} Bridge Domain(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_bds = [bd for bd in bd_names if bd not in device_bds]
            str_failed_bds = ", ".join(failed_bds) if len(failed_bds) > 1 else " ".join(failed_bds)
            summary = generate_summary(
                f"{str_failed_bds} Bridge Domain(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_aps_tenants(self):
        str_output = self.run_playbook(self.playbooks["ap"])
        # From Spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Tenant_AP_EPG")
        ap_names = [i for i, j in zip(tenant_worksheet["AP"], tenant_worksheet["State"]) if j == "present"]
        # From ACI Device
        query_output = json.loads(self.run_playbook(self.playbooks["ap"].replace("ap", "query/ap")))
        query_result = get_query_result(query_output, self.host_ip)
        device_aps = [sub for i in query_result for sub in i] if isinstance(query_result, list) else []
        results = all(ap in device_aps for ap in ap_names) if device_aps and ap_names else False
        if results:
            ap_names = set(ap_names)  # Avoid Duplicates
            str_ap_names = ", ".join(ap_names) if len(ap_names) > 1 else " ".join(ap_names)
            summary = generate_summary(
                f"{str_ap_names} Application Profile(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_aps = [ap for ap in ap_names if ap not in device_aps]
            str_failed_aps = ", ".join(failed_aps) if len(failed_aps) > 1 else " ".join(failed_aps)
            summary = generate_summary(
                f"{str_failed_aps} Application Profile(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        return results, summary + str_output

    def configure_epg_contracts_tenants(self):
        str_output = self.run_playbook(self.playbooks["epg_contract"])
        # From spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Tenant_AP_EPG")
        epg_names = [i for i, j in zip(tenant_worksheet["EPG"], tenant_worksheet["State"]) if j == "present"]
        contract_names = tenant_worksheet["Contract"].to_list()
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(self.playbooks["epg_contract"].replace("epg_contract", "query/epg_contract"))
        )
        query_result = get_query_result(query_output, self.host_ip)
        # EPGs
        epg_query_result = query_result.get("epg", {})
        device_epgs = [sub for i in epg_query_result for sub in i] if isinstance(epg_query_result, list) else []
        results_epg = all(epg in device_epgs for epg in epg_names) if device_epgs and epg_names else False
        if results_epg:
            epg_names = set(epg_names)  # Avoid Duplicates
            str_epg_names = ", ".join(epg_names) if len(epg_names) > 1 else " ".join(epg_names)
            summary = generate_summary(
                f"{str_epg_names} Application EPG(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_epgs = [epg for epg in epg_names if epg not in device_epgs]
            str_failed_epgs = ", ".join(failed_epgs) if len(failed_epgs) > 1 else " ".join(failed_epgs)
            summary = generate_summary(
                f"{str_failed_epgs} Application EPG(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        # Contracts
        contract_query_result = query_result.get("contract", {})
        device_contracts = (
            [sub for i in contract_query_result for sub in i] if isinstance(contract_query_result, list) else []
        )
        results_contracts = all(contract in device_contracts for contract in contract_names)
        if results_contracts:
            contract_names = set(contract_names)  # Avoid Duplicates
            str_contract_names = ", ".join(contract_names) if len(contract_names) > 1 else " ".join(contract_names)
            summary += generate_summary(
                f"{str_contract_names} Application Contract(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_contracts = [contract for contract in contract_names if contract not in device_contracts]
            str_failed_contracts = (
                ", ".join(failed_contracts) if len(failed_contracts) > 1 else " ".join(failed_contracts)
            )
            summary += generate_summary(
                f"{str_failed_contracts} Application Contract(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        results = results_epg and results_contracts
        return results, summary + str_output

    def deploy_interfaces_epg(self):
        str_output = self.run_playbook(self.playbooks["interface_epg_binding"])
        # From spreadsheet
        tenant_worksheet = pd.read_excel(self.destination_spreadsheet_location, sheet_name="Interface_EPG_Binding")
        tenant_worksheet = tenant_worksheet.to_dict()
        length_entries = len(tenant_worksheet["Interface_Type"])
        vpc_interfaces = []
        non_vpc_interfaces = []
        for i in range(0, length_entries):
            if tenant_worksheet["Interface_Type"][i] != "switch_port":
                vpc_interfaces.append(tenant_worksheet["Interface_Policy_GP"][i])
            else:
                non_vpc_interfaces.append(tenant_worksheet["Interface"][i])
        # From ACI Device
        query_output = json.loads(
            self.run_playbook(
                self.playbooks["interface_epg_binding"].replace("interface_epg_binding", "query/interface_epg_binding")
            )
        )
        query_result = get_query_result(query_output, self.host_ip)
        # Non VPC Interface
        non_vpc_query = query_result.get("non_vpc", {})
        device_non_vpcs = [sub for i in non_vpc_query for sub in i] if isinstance(non_vpc_query, list) else []
        results_non_vpcs = (
            all(i in j for i, j in zip(non_vpc_interfaces, device_non_vpcs)) if device_non_vpcs else False
        )
        if results_non_vpcs:
            non_vpc_interfaces = set(non_vpc_interfaces)  # Avoid Duplicates
            str_non_vpc_interfaces = (
                ", ".join(non_vpc_interfaces) if len(non_vpc_interfaces) > 1 else " ".join(non_vpc_interfaces)
            )
            summary = generate_summary(
                f"{str_non_vpc_interfaces} Non VPC Interface(s) Successfully deployed on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_non_vpc_interfaces = [non_vpc for non_vpc in non_vpc_interfaces if non_vpc not in device_non_vpcs]
            str_failed_non_vpc_interfaces = (
                ", ".join(failed_non_vpc_interfaces)
                if len(failed_non_vpc_interfaces) > 1
                else " ".join(failed_non_vpc_interfaces)
            )
            summary = generate_summary(
                f"{str_failed_non_vpc_interfaces} Non VPC Interface(s) Failed to deploy on Cisco ACI {self.host_ip}\n"
            )
        # VPC Interface
        vpc_query = query_result.get("vpc", {})
        device_vpcs = [sub for i in vpc_query for sub in i] if isinstance(vpc_query, list) else []
        results_vpcs = all(i in j for i, j in zip(vpc_interfaces, device_vpcs)) if device_vpcs else False
        if results_vpcs:
            vpc_interfaces = set(vpc_interfaces)  # Avoid Duplicates
            str_vpc_interfaces = ", ".join(vpc_interfaces) if len(vpc_interfaces) > 1 else " ".join(vpc_interfaces)
            summary += generate_summary(
                f"{str_vpc_interfaces} VPC Interface(s) Successfully configured on Cisco ACI {self.host_ip}\n"
            )
        else:
            failed_vpc_interfaces = [vpc for vpc in vpc_interfaces if vpc not in device_vpcs]
            str_failed_vpc_interfaces = (
                ", ".join(failed_vpc_interfaces) if len(failed_vpc_interfaces) > 1 else " ".join(failed_vpc_interfaces)
            )
            summary += generate_summary(
                f"{str_failed_vpc_interfaces} VPC Interface(s) Failed to configure on Cisco ACI {self.host_ip}\n"
            )
        results = results_non_vpcs and results_vpcs
        return results, summary + str_output

    def run_ansible(self, action=None):
        actions = {
            "Perform Node Registration": self.node_registration,
            "Configure OOB/INB IP Address Pool": self.configure_ip_address_pool,
            "Configure Node Management Addresses": self.configure_mgmt_node,
            "Configure Switch Policies": self.configure_switch_policies,
            "Configure Switch vPC Pairs": self.configure_switch_vpc,
            "Configure VPool, Domains, AEP": self.configure_vpool_domains_aep,
            "Configure Layer-2 Policies (LACP/LLDP/L2 Interface)": self.configure_layer2_policies,
            "Configure Interface Policy Group": self.configure_interface_policy_group,
            "Activate Switch Ports with Policy Group": self.activate_switch_ports,
            "Configure Tenants": self.configure_tenants,
            "Configure VRFs for Tenants": self.configure_vrf_tenants,
            "Configure BDs for Tenants": self.configure_bds_tenants,
            "Configure Application Profiles for Tenants": self.configure_aps_tenants,
            "Configure EPGs & Contracts for Tenants": self.configure_epg_contracts_tenants,
            "Deploy Interfaces in EPG": self.deploy_interfaces_epg,
        }
        return actions.get(action)()


class F5Manager:
    def __init__(self, credentials=None):
        if not credentials:
            credentials = dict()
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.destination_spreadsheet_location = None
        self.playbooks = {}

    def inventory_setup(self, spreadsheet_path):
        self.destination_spreadsheet_location = abs_path + "/ansible/f5/F5_Deployment_Template.xlsx"
        run(["cp", spreadsheet_path, self.destination_spreadsheet_location], stdout=PIPE)
        self.playbooks = {
            "server_config": abs_path + "/ansible/f5/playbooks/f5_dns.yml",
            "ntp_config": abs_path + "/ansible/f5/playbooks/f5_ntp.yml",
            "syslog_config": abs_path + "/ansible/f5/playbooks/f5_syslog.yml",
            "trunk_interface": abs_path + "/ansible/f5/playbooks/f5_trunk.yml",
            "vlan_config": abs_path + "/ansible/f5/playbooks/f5_vlan.yml",
            "self_ip_config": abs_path + "/ansible/f5/playbooks/f5_selfip.yml",
            "virtual_server": abs_path + "/ansible/f5/playbooks/f5_virtualserver.yml",
            "ltm_pool": abs_path + "/ansible/f5/playbooks/f5_pool.yml",
            "pool_member": abs_path + "/ansible/f5/playbooks/f5_poolmember.yml",
        }

    def run_playbook(self, playbook_name):
        output = run(
            ["ansible-playbook", playbook_name, "-e", f"username={self.username} password={self.password}", "-v"],
            stdout=PIPE,
        )
        str_output = output.stdout.decode("utf-8")
        json_output = json.loads(str_output[46:].replace("\n", ""))
        f5_logger = get_logger("f5")
        f5_logger.debug(str_output[46:])
        return json.dumps(json_output, indent=4)

    def dns_server_config(self):
        str_output = self.run_playbook(self.playbooks["server_config"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def ntp_config(self):
        str_output = self.run_playbook(self.playbooks["ntp_config"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def syslog_config(self):
        str_output = self.run_playbook(self.playbooks["syslog_config"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def trunk_interface(self):
        str_output = self.run_playbook(self.playbooks["trunk_interface"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def vlan_config(self):
        str_output = self.run_playbook(self.playbooks["vlan_config"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def self_ip_config(self):
        str_output = self.run_playbook(self.playbooks["self_ip_config"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def virtual_server(self):
        str_output = self.run_playbook(self.playbooks["virtual_server"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def ltm_pool(self):
        str_output = self.run_playbook(self.playbooks["ltm_pool"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def update_pool_member(self):
        str_output = self.run_playbook(self.playbooks["pool_member"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the F5 Device"
        summary = generate_summary(f"F5 Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def run_ansible(self, action=None):
        actions = {
            "DNS Server Configuration": self.dns_server_config,
            "NTP Configuration": self.ntp_config,
            "Syslog Configuration": self.syslog_config,
            "Trunk Interface Configuration": self.trunk_interface,
            "VLAN Configuration": self.vlan_config,
            "Self-IP Configuration": self.self_ip_config,
            "Configure LTM Virtual Server and Pool Member": self.virtual_server,
            "Configure LTM Pool and Pool Member": self.ltm_pool,
            "Update LTM Virtual Server": self.virtual_server,
            "Update LTM Pool Member(s)": self.update_pool_member,
        }
        return actions.get(action)()


class IOSManager:
    def __init__(self):
        self.destination_spreadsheet_location = None
        self.inventory_file_location = None
        self.playbooks = {}

    def inventory_setup(self, spreadsheet_path, inventory_path):
        self.destination_spreadsheet_location = abs_path + "/ansible/ios/IOS_Deployment_Template.xlsx"
        self.inventory_file_location = abs_path + "/ansible/ios/playbooks/inventory.yml"
        run(["cp", spreadsheet_path, self.destination_spreadsheet_location], stdout=PIPE)
        run(["cp", inventory_path, self.inventory_file_location], stdout=PIPE)
        self.playbooks = {
            "inventory": self.inventory_file_location,
            "config_host": abs_path + "/ansible/ios/playbooks/Hostsystem.yml",
            "ntp_config": abs_path + "/ansible/ios/playbooks/NTP.yml",
            "banner_config": abs_path + "/ansible/ios/playbooks/Banner.yml",
            "aaa_config": abs_path + "/ansible/ios/playbooks/AAA.yml",
            "snmp_config": abs_path + "/ansible/ios/playbooks/SNMP.yml",
            "syslog_config": abs_path + "/ansible/ios/playbooks/Syslog.yml",
            "stp_config": abs_path + "/ansible/ios/playbooks/STP.yml",
            "linkagg_group": abs_path + "/ansible/ios/playbooks/linkagg.yml",
            "l2_interface": abs_path + "/ansible/ios/playbooks/L2_interfaces.yml",
            "vlan_config": abs_path + "/ansible/ios/playbooks/Vlan.yml",
            "l3_interface": abs_path + "/ansible/ios/playbooks/L3.yml",
            "hsrp_config": abs_path + "/ansible/ios/playbooks/HSRP.yml",
            "vrrp_config": abs_path + "/ansible/ios/playbooks/VRRP.yml",
            "ospf_config": abs_path + "/ansible/ios/playbooks/OSPF.yml",
            "ospf_interface": abs_path + "/ansible/ios/playbooks/OSPF_Interface.yml",
            "bfd_config": abs_path + "/ansible/ios/playbooks/BFD.yml",
            "bgp_config": abs_path + "/ansible/ios/playbooks/BGP.yml",
            "static_route": abs_path + "/ansible/ios/playbooks/StaticRoute.yml",
            "vrf_config": abs_path + "/ansible/ios/playbooks/VRF.yml"
        }

    def run_playbook(self, playbook_name):
        output = run(
            ["ansible-playbook", "-i", self.playbooks["inventory"], playbook_name, "-v"],
            stdout=PIPE,
        )
        str_output = output.stdout.decode("utf-8")
        json_output = json.loads(str_output[46:].replace("\n", ""))
        ios_logger = get_logger("ios")
        ios_logger.debug(str_output[46:])
        return json.dumps(json_output, indent=4)

    def config_host(self):
        str_output = self.run_playbook(self.playbooks["config_host"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def ntp_config(self):
        str_output = self.run_playbook(self.playbooks["ntp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def banner_config(self):
        str_output = self.run_playbook(self.playbooks["banner_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def aaa_config(self):
        str_output = self.run_playbook(self.playbooks["aaa_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def snmp_config(self):
        str_output = self.run_playbook(self.playbooks["snmp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def syslog_config(self):
        str_output = self.run_playbook(self.playbooks["syslog_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def stp_config(self):
        str_output = self.run_playbook(self.playbooks["stp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def linkagg_group(self):
        str_output = self.run_playbook(self.playbooks["linkagg_group"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def l2_interface(self):
        str_output = self.run_playbook(self.playbooks["l2_interface"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def vlan_config(self):
        str_output = self.run_playbook(self.playbooks["vlan_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def l3_interface(self):
        str_output = self.run_playbook(self.playbooks["l3_interface"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def hsrp_config(self):
        str_output = self.run_playbook(self.playbooks["hsrp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def vrrp_config(self):
        str_output = self.run_playbook(self.playbooks["vrrp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def ospf_config(self):
        str_output = self.run_playbook(self.playbooks["ospf_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def ospf_interface(self):
        str_output = self.run_playbook(self.playbooks["ospf_interface"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def bfd_config(self):
        str_output = self.run_playbook(self.playbooks["bfd_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def bgp_config(self):
        str_output = self.run_playbook(self.playbooks["bgp_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def static_route(self):
        str_output = self.run_playbook(self.playbooks["static_route"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def vrf_config(self):
        str_output = self.run_playbook(self.playbooks["vrf_config"])
        json_output = json.loads(str_output)
        result = any(jmespath.search("stats.*.failures", json_output) or [])
        execution_res = "FAIL" if result else "PASS"
        verify = f"Verify the changes on the IOS Device"
        summary = generate_summary(f"IOS Execution Results = {execution_res}\n{verify}\n")
        return not result, summary + str_output

    def run_ansible(self, action=None):
        actions = {
            "Configure host system parameters": self.config_host,
            "Configure NTP": self.ntp_config,
            "Configure motd and login Banner": self.banner_config,
            "Configure AAA": self.aaa_config,
            "Configure SNMP": self.snmp_config,
            "Configure System Logging": self.syslog_config,
            "Configure STP": self.stp_config,
            "Configure Aggregation group": self.linkagg_group,
            "Configure L2 interfaces": self.l2_interface,
            "Configure VLANs": self.vlan_config,
            "Configure L3 interface IP": self.l3_interface,
            "Configure HSRP": self.hsrp_config,
            "Configure VRRP": self.vrrp_config,
            "Configure OSPF": self.ospf_config,
            "Configure OSPF for interfaces": self.ospf_interface,
            "Configure BFD": self.bfd_config,
            "Configure BGP": self.bgp_config,
            "Configure Static Route": self.static_route,
            "Configure VRF": self.vrf_config,
        }
        return actions.get(action)()



class vManageManager:
    def __init__(self, credentials=None):
        if not credentials:
            credentials = dict()
        self.host_ip = credentials["host_ip"]
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.destination_spreadsheet_location = None
        self.playbooks = {}

    def inventory_setup(self, spreadsheet_path):
        self.destination_spreadsheet_location = abs_path + "/ansible/sdwan/SDWAN_Deployment_Template.xlsx"
        run(["cp", spreadsheet_path, self.destination_spreadsheet_location], stdout=PIPE)
        self.playbooks = {
            "AAA": abs_path + "/ansible/sdwan/playbooks/AAA.yml",
            "BFD": abs_path + "/ansible/sdwan/playbooks/BFD.yml",
            "Delete Feature Template": abs_path + "/ansible/sdwan/playbooks/Delete_Feature_Template.yml",
        }

    def run_playbook(self, playbook_name):
        output = run(
            ["ansible-playbook", playbook_name, "-e", f"host_ip={self.host_ip} username={self.username} password={self.password}", "-v"],
            stdout=PIPE,
        )
        str_output = output.stdout.decode("utf-8")
        json_output = json.loads(str_output[46:].replace("\n", ""))
        sdwan_logger = get_logger("viptela")
        sdwan_logger.debug(str_output[46:])
        return json.dumps(json_output, indent=4)

    def aaa_config(self):
        str_output = self.run_playbook(self.playbooks["AAA"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the vManage Device"
        summary = generate_summary(f"vManage Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def bfd_config(self):
        str_output = self.run_playbook(self.playbooks["BFD"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the vManage Device"
        summary = generate_summary(f"vManage Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def delete_feature_template(self):
        str_output = self.run_playbook(self.playbooks["Delete Feature Template"])
        json_output = json.loads(str_output)
        result = False if json_output.get("stats", {}).get("localhost", {}).get("failures", {}) else True
        execution_res = "PASS" if result else "FAIL"
        verify = f"Verify the changes on the vManage Device"
        summary = generate_summary(f"vManage Execution Results = {execution_res}\n{verify}\n")
        return result, summary + str_output

    def run_ansible(self, action=None):
        actions = {
            "AAA": self.aaa_config,
            "BFD": self.bfd_config,
            "Delete Feature Template": self.delete_feature_template,
        }
        return actions.get(action)()
