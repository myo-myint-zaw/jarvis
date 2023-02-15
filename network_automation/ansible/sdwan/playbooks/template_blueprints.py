"""
Complete list of template blueprints
"""

__all__ = ['AaaUser', 'AaaTacacs', 'AaaTemplate', 'BfdTemplate', 'NtpServers', 'NtpTemplate', 'OmpIpv4', 'OmpIpv6', 'OmpTemplate', 
'SecurityTemplate', 'Vpn0DnsServers', 'NullDnsServer', 'Vpn0Template', 'VpnOthersIpv4', 'VpnOthersIpv6', 'VpnOthersTemplate', 'VpnEthernetTemplate', 
'BannerTemplate', 'LoggingServersIpv4', 'LoggingTemplate', 'OspfRedistribute', 'OspfTemplate', 
'TrapServer', 'TrapModule', 'Snmpv2Template', 'TrapServerV3', 'TrapModuleV3', 'SnmpUser', 'Snmpv3Template', 'OspfInterface', 'OspfAreaANumM', 'OspfAreaANumD']


# Global
template_version = "15.0.0"


# Complete list of Feature Templates blueprints
# AAA Feature Template
class AaaUser:
    def __init__(self, username, u_description, password, group):
        self.aaa_user = {
            "vipOptional": False,
            "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": username,
                "vipVariableName": "user_name_0"
            },
            "password": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": password,
                "vipVariableName": "undefined_password"
            },
            "secret": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": "$9$4F2F2lEE1k$BGmuXOLzVCd2",
                "vipVariableName": "undefined_secret"
            },
            "description": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": u_description,
                "vipVariableName": "user_description"
            },
            "group": {
                "vipType": "constant",
                "vipObjectType": "list",
                "vipVariableName": "user_group",
                "vipValue": [
                    {
                        "vipType": "constant",
                        "vipValue": group,
                        "vipObjectType": "object"
                    }
                ]
            },
            "priority-order": [
                "name",
                "password",
                "secret",
                "description",
                "group"
            ]
        }

    def to_json(self):
        return self.aaa_user


class AaaTacacs:
    def __init__(self, tacacs_server, s_interface, vpn, priority, secret_key):
        self.aaa_tacacs = {
            "address": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": tacacs_server,
                "vipVariableName": "tacacs_tacacs_address"
            },
            "auth-port": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": 49,
                "vipVariableName": "tacacs_tacacs_auth_port"
            },
            "vpn": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": vpn,
                "vipVariableName": "tacacs_tacacs_vpn"
            },
            "source-interface": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": s_interface,
                "vipVariableName": "tacacs_tacacs_source_interface"
            },
            "key": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "tacacs_tacacs_key"
            },
            "secret-key": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": secret_key,
                "vipVariableName": "tacacs_tacacs_secret_key"
            },
            "priority": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": priority,
                "vipVariableName": "tacacs_tacacs_priority"
            },
            "priority-order": [
                "address",
                "auth-port",
                "vpn",
                "source-interface",
                "key",
                "secret-key",
                "priority"
            ]
        }

    def to_json(self):
        return self.aaa_tacacs


class AaaTemplate:
    def __init__(self, name, description, device_type, device_model, auth1, auth2, auth3, fallback, order_on, aaa_user, timeout, auth_method, tacacs_servers):
        self.aaa = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "aaa",
            "templateMinVersion": template_version,
            "userGroupName": {
                "key": "name",
                "description": "Name",
                "details": "Set name of user group",
                "optionType": [
                    {
                        "value": "constant",
                        "display": "Global",
                        "iconClass": "language",
                        "iconColor": "icon-global"
                    }
                ],
                "originalDefaultOption": "constant",
                "defaultOption": "constant",
                "dataType": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128
                },
                "dataPath": [],
                "vipObjectType": "object",
                "objectType": "object",
                "deleteFlag": True
            },
            "templateDefinition": {
                "aaa": {
                    "auth-order": {
                        "vipType": "constant",
                        "vipValue": [
                            {
                                "vipType": "constant",
                                "vipValue": auth1,
                                "vipObjectType": "object"
                            },
                            {
                                "vipType": "constant",
                                "vipValue": auth2,
                                "vipObjectType": "object"
                            },
                            {
                                "vipType": "constant",
                                "vipValue": auth3,
                                "vipObjectType": "object"
                            }
                        ],
                        "vipObjectType": "list",
                        "vipVariableName": "auth_order"
                    },
                    "auth-fallback": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": fallback,
                        "vipVariableName": "auth_fallback"
                    },
                    "admin-auth-order": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": order_on,
                        "vipVariableName": "admin_auth_order"
                    },
                    "logs": {
                        "audit-disable": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": "true",
                            "vipVariableName": "disable_audit_logs"
                        },
                        "netconf-disable": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": True,
                            "vipVariableName": "disable_netconf_logs"
                        }
                    },
                    "radius-servers": {
                        "vipObjectType": "list",
                        "vipType": "ignore",
                        "vipValue": [ "" ],
                        "vipVariableName": "radius_servers"
                    },
                    "usergroup": {
                        "vipType": "constant",
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [ "name" ],
                        "vipValue": [
                            {
                                "name": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": "netadmin"
                                },
                                "viewMode": "view",
                                "priority-order": [ "name" ]
                            },
                            {
                                "name": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": "basic"
                                },
                                "priority-order": [
                                    "name",
                                    "task"
                                ],
                                "task": {
                                    "vipType": "constant",
                                    "vipValue": [
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "system",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    },
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "write",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        },
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "interface",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    },
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "write",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        }
                                    ],
                                    "vipObjectType": "tree",
                                    "vipPrimaryKey": [ "mode" ]
                                }
                            },
                            {
                                "name": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": "operator"
                                },
                                "priority-order": [
                                    "name",
                                    "task"
                                ],
                                "task": {
                                    "vipType": "constant",
                                    "vipValue": [
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "system",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        },
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "interface",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        },
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "policy",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        },
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "routing",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        },
                                        {
                                            "mode": {
                                                "vipType": "constant",
                                                "vipValue": "security",
                                                "vipObjectType": "object"
                                            },
                                            "permission": {
                                                "vipType": "constant",
                                                "vipValue": [
                                                    {
                                                        "vipType": "constant",
                                                        "vipValue": "read",
                                                        "vipObjectType": "object"
                                                    }
                                                ],
                                                "vipObjectType": "list"
                                            },
                                            "priority-order": [
                                                "mode",
                                                "permission"
                                            ]
                                        }
                                    ],
                                    "vipObjectType": "tree",
                                    "vipPrimaryKey": [ "mode" ]
                                }
                            }
                        ]
                    },
                    "user": {
                        "vipOptional": False,
                        "vipType": "constant",
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [ "name" ],
                        "vipValue": aaa_user,
                    }
                },
                "tacacs": {
                    "timeout": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": timeout,
                        "vipVariableName": "tacacs_timeout",
                    },
                    "authentication": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": auth_method,
                        "vipVariableName": "tacacs_authentication"
                    },
                    "server": {
                        "vipType": "constant",
                        "vipValue": tacacs_servers,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [ "address" ]
                    }
                },
                "radius": {
                    "timeout": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 5,
                        "vipVariableName": "radius_timeout"
                    },
                    "retransmit": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 3,
                        "vipVariableName": "retransmit"
                    }
                }
            }
        }

    def to_json(self):
        return self.aaa


# BFD Feature Template
class BfdTemplate:
    def __init__(self, name, description, device_type, device_model, multiplier, poll_interval, color, hello, hello_multi, pmtu_discovery):
        self.bfd = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "bfd-vedge",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "app-route": {
                    "multiplier": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": multiplier,
                        "vipVariableName": "bfd_multiplier"
                    },
                    "poll-interval": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": poll_interval,
                        "vipVariableName": "bfd_poll_interval"
                    }
                },
                "color": {
                    "vipType": "constant",
                    "vipValue": [
                        {
                            "color": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": color,
                                "vipVariableName": "bfd_color"
                            },
                            "hello-interval": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": hello,
                                "vipVariableName": "bfd_hello_interval"
                            },
                            "multiplier": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": hello_multi,
                                "vipVariableName": "bfd_color_multiplier"
                            },
                            "pmtu-discovery": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": pmtu_discovery,
                                "vipVariableName": "bfd_pmtu_discovery"
                            },
                            "priority-order": [
                                "color",
                                "hello-interval",
                                "multiplier",
                                "pmtu-discovery"
                            ]
                        }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "color"
                    ]
                }
            }
        }

    def to_json(self):
        return self.bfd

# NTP Feature Template
class NtpServers:
    def __init__(self, ip, vpn, interface, prefer):
        self.ntp_server = {
            "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": ip,
                "vipVariableName": "ntp_server_host",
            },
            "key": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "1",
                "vipVariableName": "ntp_server_server_auth_key",
            },
            "vpn": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn),
                "vipVariableName": "ntp_server_vpn",
            },
            "version": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "4",
                "vipVariableName": "ntp_server_version",
            },
            "source-interface": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": interface,
                "vipVariableName": "ntp_server_source_interface",
            },
            "prefer": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": prefer,
                "vipVariableName": "ntp_server_prefer",
            },
            "priority-order": ["name", "key", "vpn", "version", "source-interface", "prefer"],
        }

    def to_json(self):
        return self.ntp_server


class NtpTemplate:
    def __init__(self, name, description, device_type, device_model, ntp_servers):
    # def __init__(self, name, description, device_type, display_name, device_model, ntp_servers):
        self.ntp = {
          "deviceType": device_type,
          "deviceModels": device_model,
          "feature": "vmanage-default",
          "factoryDefault": False,
          "templateName": name,
          "templateDescription": description,
          "templateType": "ntp",
          "templateMinVersion": template_version,
            "templateDefinition": {
                "keys": {
                    "trusted": {
                        "vipObjectType": "list",
                        "vipType": "ignore",
                        "vipValue": "1",
                        "vipVariableName": "trusted_key",
                    }
                },
                "server": {
                    "vipType": "constant",
                    "vipValue": ntp_servers,
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["name"],
                }
            }
        }

    def to_json(self):
        return self.ntp




# OMP Feature Template
class OmpIpv4:
    def __init__(self, v4_type):
        self.omp_ipv4 = {
            "priority-order": [
                "protocol"
            ],
            "protocol": {
                "vipType": "constant",
                "vipValue": v4_type,
                "vipObjectType": "object"
            }
        },
        self.omp_ospf = {
            "priority-order": [
                "protocol"
            ],
            "protocol": {
                "vipType": "constant",
                "vipValue": v4_type,
                "vipObjectType": "object"
            },
            "route": {
                "vipType": "constant",
                "vipValue": "external",
                "vipObjectType": "object"
            }
        }
    def to_json(self):
        return self.omp_ipv4

    def to_json_ospf(self):
        return self.omp_ospf


class OmpIpv6:
    def __init__(self, v6_type):
        self.omp_ipv6 = {
            "priority-order": [
                "protocol"
            ],
            "protocol": {
                "vipType": "constant",
                "vipValue": v6_type,
                "vipObjectType": "object"
            }
        }

    def to_json(self):
        return self.omp_ipv6


class OmpTemplate:
    def __init__(self, name, description, device_type, device_model, gr, shutdown, adv_int, hold_time, omp_ipv4, omp_ipv6):
        self.omp = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "omp-vedge",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "graceful-restart": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": gr,
                    "vipVariableName": "omp_graceful_restart"
                },
                "send-path-limit": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 4,
                    "vipVariableName": "omp_send_path_limit"
                },
                "overlay-as": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "",
                    "vipVariableName": "overlay_as"
                },
                "ecmp-limit": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 4,
                    "vipVariableName": "omp_ecmp_limit"
                },
                "shutdown": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": shutdown,
                    "vipVariableName": "omp_shutdown"
                },
                "timers": {
                    "advertisement-interval": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": int(adv_int),
                        "vipVariableName": "omp_advertisement_interval"
                    },
                    "graceful-restart-timer": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 43200,
                        "vipVariableName": "omp_graceful_restart_timer"
                    },
                    "holdtime": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": int(hold_time),
                        "vipVariableName": "omp_holdtime"
                    },
                    "eor-timer": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 300,
                        "vipVariableName": "omp_eor_timer"
                    }
                },
                "advertise": {
                    "vipType": "constant",
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "protocol"
                    ],
                    "vipValue": omp_ipv4
                },
                "ipv6-advertise": {
                    "vipType": "constant",
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "protocol"
                    ],
                    "vipValue": omp_ipv6
                }
            }
        }

    def to_json(self):
        return self.omp


# Security Feature Template
class SecurityTemplate:
    def __init__(self, name, description, device_type, device_model, rekey, replay, auth_type):
        self.security = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "security-vedge",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "ipsec": {
                    "rekey": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        "vipValue": int(rekey),
                        "vipVariableName": "security_rekey"
                    },
                    "replay-window": {
                        "vipObjectType": "object",
                        "vipType": "constant",
                        # "vipValue": f"{replay}",
                        "vipValue": str(replay),
                        "vipVariableName": "security_replay_window"
                    },
                    "authentication-type": {
                        "vipType": "constant",
                        "vipValue": auth_type,
                        "vipObjectType": "list",
                        "vipVariableName": "security_authenticationType"
                    }
                }
            }
        }

    def to_json(self):
        return self.security


# VPN0 Feature Template
class Vpn0DnsServers:
    def __init__(self, server, role):
        self.vpn0_dns_servers = {
            "role": {
                "vipType": "constant",
                "vipValue": role,
                "vipObjectType": "object"
            },
            "dns-addr": {
                "vipType": "constant",
                "vipValue": server,
                "vipObjectType": "object"
            },
            "priority-order": [
                "dns-addr",
                "role"
            ]
        }


    def to_json(self):
        return self.vpn0_dns_servers


class NullDnsServer:
    def __init__(self):
        self.null_dns_server = {
            "role": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "object"
            },
            "dns-addr": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "object"
            },
            "priority-order": [
                "dns-addr",
                "role"
            ]
        }


    def to_json(self):
        return self.null_dns_server


class Vpn0Template:
    def __init__(self, name, description, device_type, device_model, vpn, vpn_name, ecmp, dns_servers, v4_route_prefix, next_hop_name, vipType):
        self.vpn0 = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "vpn-vedge",
            "templateMinVersion": template_version,
            "factoryDefault": False,
            "templateDefinition": {
                "vpn-id": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn)
                },
                "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": vpn_name,
                "vipVariableName": "vpn_name"
                },
                "ecmp-hash-key": {
                "layer4": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": ecmp,
                    "vipVariableName": "vpn_layer4"
                }
                },
                "tcp-optimization": {
                "vipObjectType": "node-only",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_tcp_optimization"
                },
                "nat64-global": {
                "prefix": {
                    "stateful": {}
                }
                },
                "nat64": {
                "v4": {
                    "pool": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["name"]
                    }
                }
                },
                "route-import": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": ["protocol"]
                },
                "route-export": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": ["protocol"]
                },
                "dns": {
                    "vipType": vipType,
                    "vipValue": dns_servers,
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["dns-addr"]
                },
                "host": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["hostname"]
                },
                "service": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": ["svc-type"]
                },
                "ip": {
                    "route": {
                        "vipType": "constant",
                        "vipValue": [
                            {
                                "prefix": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": v4_route_prefix,
                                    "vipVariableName": "vpn_ipv4_ip_prefix"
                                },
                                "next-hop": {
                                    "vipType": "constant",
                                    "vipValue": [
                                        {
                                            "address": {
                                                "vipObjectType": "object",
                                                "vipType": "variableName",
                                                "vipValue": "",
                                                "vipVariableName": next_hop_name
                                            },
                                            "distance": {
                                                "vipObjectType": "object",
                                                "vipType": "notIgnore",
                                                "vipValue": 1,
                                                "vipVariableName": "vpn_next_hop_ip_distance_0"
                                            },
                                            "tracker": {
                                                "vipObjectType": "object",
                                                "vipType": "ignore",
                                                "vipValue": "",
                                                "vipVariableName": "vpn_next_hop_ip_tracker_0"
                                            },
                                            "priority-order": [
                                                "address",
                                                "distance",
                                                "tracker"
                                            ]
                                        }
                                    ],
                                    "vipObjectType": "tree",
                                    "vipPrimaryKey": [ "address" ]
                                },
                                "priority-order": [
                                    "prefix",
                                    "next-hop"
                                ]
                            }
                        ],
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [ "prefix" ]
                    },
                    "gre-route": {},
                    "ipsec-route": {},
                    "service-route": {}
                },
                "ipv6": {},
                "omp": {
                    "advertise": {
                        "vipType": "ignore",
                        "vipValue": [],
                        "vipObjectType": "tree",
                        "vipPrimaryKey": ["protocol"]
                    },
                    "distance": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": "",
                        "vipVariableName": "vpn_distance"
                    },
                    "ipv6-advertise": {
                        "vipType": "ignore",
                        "vipValue": [],
                        "vipObjectType": "tree",
                        "vipPrimaryKey": ["protocol"]
                    }
                }
            }
        }


    def to_json(self):
        return self.vpn0


# VPN Others Feature Template
class VpnOthersIpv4:
    def __init__(self, v4_type):
        self.vpnothers_ipv4 = {
            "priority-order": [
            "protocol"
            ],
            "protocol": {
            "vipType": "constant",
            "vipValue": v4_type,
            "vipObjectType": "object"
            }
        },
        self.vpnothers_ospf = {
            "priority-order": [
              "protocol",
              "protocol-sub-type"
            ],
            "protocol": {
              "vipType": "constant",
              "vipValue": v4_type,
              "vipObjectType": "object"
            },
            "protocol-sub-type": {
              "vipType": "constant",
              "vipValue": "external",
              "vipObjectType": "object"
            }
        }

    def to_json(self):
        return self.vpnothers_ipv4

    def to_json_ospf(self):
        return self.vpnothers_ospf

class VpnOthersIpv6:
    def __init__(self, v6_type):
        self.vpnothers_ipv6 = {
            "priority-order": [
              "protocol"
            ],
            "protocol": {
              "vipType": "constant",
              "vipValue": v6_type,
              "vipObjectType": "object",
              "ipType": "ipv6"
            }
        }

    def to_json(self):
        return self.vpnothers_ipv6



class VpnOthersTemplate:
    def __init__(self, name, description, device_type, device_model, vpn, vpn_name, ecmp, v4_advertise, v6_advertise):
        self.vpnothers = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "vpn-vedge",
            "templateMinVersion": template_version,
            "factoryDefault": False,
            "templateDefinition": {
                "vpn-id": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn)
                },
                "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": vpn_name,
                "vipVariableName": "vpn_name"
                },
                "ecmp-hash-key": {
                "layer4": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": ecmp,
                    "vipVariableName": "vpn_layer4"
                }
                },
                "tcp-optimization": {
                "vipObjectType": "node-only",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_tcp_optimization"
                },
                "nat64-global": {
                "prefix": {
                    "stateful": {}
                }
                },
                "nat64": {
                "v4": {
                    "pool": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name"
                    ]
                    }
                }
                },
                "route-import": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "protocol"
                ]
                },
                "route-export": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "protocol"
                ]
                },
                "host": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "hostname"
                    ]
                },
                "service": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "svc-type"
                ]
                },
                "ip": {
                "gre-route": {},
                "ipsec-route": {},
                "service-route": {}
                },
                "ipv6": {},
                "omp": {
                    "advertise": {
                        "vipType": "constant",
                        "vipValue": v4_advertise,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                        "protocol"
                        ]
                    },
                    "distance": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": "",
                        "vipVariableName": "vpn_distance"
                    },
                    "ipv6-advertise": {
                        "vipType": "constant",
                        "vipValue": v6_advertise,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                        "protocol"
                        ]
                    }
                }
            }
        }

    def to_json(self):
        return self.vpnothers


# VPN Interface Ethernet Feature Template
class VpnEthernetTemplate:
    def __init__(self, name, description, device_type, device_model, int_name, shutdown, int_description, ipv4_address_name, color, groups, 
    max_control_connections, port_hop, mtu, bgp, dhcp, dns, icmp, netconf, ntp, ospf, ssh, stun, https, ipsec):
        self.vpnethernet = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "vpn-vedge-interface",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "if-name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int_name,
                "vipVariableName": "vpn_if_name"
                },
                "description": {
                "vipObjectType": "object",
                "vipType": "variableName",
                "vipValue": "",
                "vipVariableName": int_description
                },
                "ip": {
                "address": {
                    "vipObjectType": "object",
                    "vipType": "variableName",
                    "vipValue": "",
                    "vipVariableName": ipv4_address_name
                },
                "secondary-address": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "address"
                    ]
                }
                },
                "dhcp-helper": {
                "vipObjectType": "list",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_dhcp_helper"
                },
                "flow-control": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "autoneg",
                "vipVariableName": "vpn_if_flow_control"
                },
                "clear-dont-fragment": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_if_clear_dont_fragment"
                },
                "pmtu": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_if_pmtu"
                },
                "mtu": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": mtu,
                "vipVariableName": "vpn_if_ip_mtu"
                },
                "static-ingress-qos": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_static_ingress_qos"
                },
                "tcp-mss-adjust": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_tcp_mss_adjust"
                },
                "mac-address": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_mac_address"
                },
                "speed": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "_empty",
                "vipVariableName": "vpn_if_speed"
                },
                "duplex": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "_empty",
                "vipVariableName": "vpn_if_duplex"
                },
                "shutdown": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": shutdown,
                "vipVariableName": "vpn_if_shutdown"
                },
                "arp-timeout": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": 1200,
                "vipVariableName": "vpn_if_arp_timeout"
                },
                "autonegotiate": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "true",
                "vipVariableName": "vpn_if_autonegotiate"
                },
                "shaping-rate": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "qos_shaping_rate"
                },
                "qos-map": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "qos_map"
                },
                "tracker": {
                "vipObjectType": "list",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_tracker"
                },
                "bandwidth-upstream": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_bandwidth_upstream"
                },
                "bandwidth-downstream": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_bandwidth_downstream"
                },
                "block-non-source-ip": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_if_block_non_source_ip"
                },
                "rewrite-rule": {
                "rule-name": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "rewrite_rule_name"
                }
                },
                "tloc-extension": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "vpn_if_tloc_extension"
                },
                "icmp-redirect-disable": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_if_icmp_redirect_disable"
                },
                "tloc-extension-gre-from": {
                "src-ip": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "vpn_if_tloc-ext_gre_from_src_ip"
                },
                "xconnect": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "vpn_if_tloc-ext_gre_from_xconnect"
                }
                },
                "access-list": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "direction"
                ]
                },
                "policer": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "policer-name",
                    "direction"
                ]
                },
                "tunnel-interface": {
                "encapsulation": {
                    "vipType": "constant",
                    "vipValue": [
                    {
                        "preference": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipVariableName": "vpn_if_tunnel_ipsec_preference"
                        },
                        "weight": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 1,
                        "vipVariableName": "vpn_if_tunnel_ipsec_weight"
                        },
                        "encap": {
                        "vipType": "constant",
                        "vipValue": ipsec,
                        "vipObjectType": "object"
                        },
                        "priority-order": [
                        "encap",
                        "preference",
                        "weight"
                        ]
                    }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "encap"
                    ]
                },
                "group": {
                    "vipObjectType": "list",
                    "vipType": "constant",
                    "vipValue": [
                    int(groups)
                    ],
                    "vipVariableName": "vpn_if_tunnel_group"
                },
                "border": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_border"
                },
                "color": {
                    "value": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": color,
                    "vipVariableName": "vpn_if_tunnel_color_value"
                    },
                    "restrict": {
                    "vipObjectType": "node-only",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_color_restrict"
                    }
                },
                "carrier": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "default",
                    "vipVariableName": "vpn_if_tunnel_carrier"
                },
                "bind": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "vpn_if_tunnel_bind"
                },
                "allow-service": {
                    "dhcp": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": dhcp,
                    "vipVariableName": "vpn_if_tunnel_dhcp"
                    },
                    "dns": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": dns,
                    "vipVariableName": "vpn_if_tunnel_dns"
                    },
                    "icmp": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": icmp,
                    "vipVariableName": "vpn_if_tunnel_icmp"
                    },
                    "sshd": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": ssh,
                    "vipVariableName": "vpn_if_tunnel_sshd"
                    },
                    "ntp": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": ntp,
                    "vipVariableName": "vpn_if_tunnel_ntp"
                    },
                    "stun": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": stun,
                    "vipVariableName": "vpn_if_tunnel_stun"
                    },
                    "all": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_all"
                    },
                    "bgp": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": bgp,
                    "vipVariableName": "vpn_if_tunnel_bgp"
                    },
                    "ospf": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": ospf,
                    "vipVariableName": "vpn_if_tunnel_ospf"
                    },
                    "netconf": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": netconf,
                    "vipVariableName": "vpn_if_tunnel_netconf"
                    },
                    "snmp": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false"
                    },
                    "https": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": https,
                    "vipVariableName": "vpn_if_tunnel_https"
                    }
                },
                "max-control-connections": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": int(max_control_connections),
                    "vipVariableName": "vpn_if_tunnel_max_control_connections"
                },
                "vbond-as-stun-server": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_vbond_as_stun_server"
                },
                "exclude-controller-group-list": {
                    "vipObjectType": "list",
                    "vipType": "ignore",
                    "vipVariableName": "vpn_if_tunnel_exclude_controller_group_list"
                },
                "vmanage-connection-preference": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 5,
                    "vipVariableName": "vpn_if_tunnel_vmanage_connection_preference"
                },
                "port-hop": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": port_hop,
                    "vipVariableName": "vpn_if_tunnel_port_hop"
                },
                "low-bandwidth-link": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_low_bandwidth_link"
                },
                "last-resort-circuit": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_tunnel_last_resort_circuit"
                },
                "hold-time": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 7000,
                    "vipVariableName": "hold-time"
                },
                "nat-refresh-interval": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 5,
                    "vipVariableName": "vpn_if_tunnel_nat_refresh_interval"
                },
                "hello-interval": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 1000,
                    "vipVariableName": "vpn_if_tunnel_hello_interval"
                },
                "hello-tolerance": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": 12,
                    "vipVariableName": "vpn_if_tunnel_hello_tolerance"
                },
                "tloc-extension-gre-to": {
                    "dst-ip": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "vpn_if_tunnel_tloc_ext_gre_to_dst_ip"
                    }
                }
                },
                "ip-directed-broadcast": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipValue": "false",
                "vipVariableName": "vpn_if_ip-directed-broadcast"
                },
                "ipv6": {
                "access-list": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "direction"
                    ]
                },
                "address": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "",
                    "vipVariableName": "vpn_if_ipv6_ipv6_address"
                },
                "dhcp-helper-v6": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "address"
                    ]
                },
                "secondary-address": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "address"
                    ]
                },
                "ipv6-shutdown": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipValue": "false",
                    "vipVariableName": "vpn_if_ipv6_ipv6_shutdown"
                }
                },
                "arp": {
                "ip": {
                    "vipType": "ignore",
                    "vipValue": [],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                    "addr"
                    ]
                }
                },
                "vrrp": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "grp-id"
                ]
                },
                "ipv6-vrrp": {
                "vipType": "ignore",
                "vipValue": [],
                "vipObjectType": "tree",
                "vipPrimaryKey": [
                    "grp-id"
                ]
                },
                "dot1x": {
                "vipType": "ignore",
                "vipObjectType": "node-only"
                }
            }
        }

    def to_json(self):
        return self.vpnethernet


# Banner Feature Template
class BannerTemplate:
    def __init__(self, name, description, device_type, device_model, login, motd):
        self.banner = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "banner",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "login": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": login,
                    "vipVariableName": "login_banner",
                },
                "motd": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": motd,
                    "vipVariableName": "motd_banner",
                },
            }
        }

    def to_json(self):
        return self.banner



# Logging Feature Template
class LoggingServersIpv4:
    def __init__(self, server_ip, vpn, src_int, priority):
        self.logging_servers_v4 = {
            "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": server_ip,
                "vipVariableName": "logging_server_name"
            },
            "vpn": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn),
                "vipVariableName": "logging_server_vpn"
            },
            "source-interface": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": src_int,
                "vipVariableName": "logging_server_source_interface"
            },
            "priority": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": priority,
                "vipVariableName": "logging_server_server_priority",
            },
            "priority-order": ["name", "vpn", "source-interface", "priority"],
        }

    def to_json(self):
        return self.logging_servers_v4


class LoggingTemplate:
    def __init__(self, name, description, device_type, device_model, logging_servers):
        self.logging = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "logging",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "disk": {
                    "enable": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": 1,
                        "vipVariableName": "logging_disk_enable",
                    },
                    "file": {
                        "size": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 1,
                            "vipVariableName": "logging_max_file_size",
                        },
                        "rotate": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 1,
                            "vipVariableName": "logging_disk_rotation",
                        },
                    },
                    "priority": {
                        "vipObjectType": "object",
                        "vipType": "ignore",
                        "vipValue": "information",
                        "vipVariableName": "logging_disk_priority",
                    },
                },
                "server": {
                    "vipType": "constant",
                    "vipValue": logging_servers,
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["name"],
                }
            }
        }

    def to_json(self):
        return self.logging



# OSPF Feature Template
class OspfRedistribute:
    def __init__(self, protocol):
        self.ospf_redistribute = {
            "protocol": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": protocol,
                "vipVariableName": "ospf_redistribute_protocol"
            },
            "route-policy": {
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "ospf_redistribute_route_policy"
            },
            "priority-order": [
                "protocol",
                "route-policy"
            ]
        }

    def to_json(self):
        return self.ospf_redistribute


class OspfTemplate:
    def __init__(self, name, description, device_type, device_model, router_id, redis_protocol):
        self.ospf = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "ospf",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "ospf": {
                    "router-id": {
                        "vipObjectType": "object",
                        "vipType": "variableName",
                        "vipValue": "",
                        "vipVariableName": router_id
                    },
                    "auto-cost": {
                        "reference-bandwidth": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 100,
                            "vipVariableName": "ospf_reference_bandwidth"
                        }
                    },
                    "compatible": {
                        "rfc1583": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": "true",
                            "vipVariableName": "ospf_rfc1583"
                        }
                    },
                    "distance": {
                        "external": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 110,
                            "vipVariableName": "ospf_distance_external"
                        },
                        "inter-area": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 110,
                            "vipVariableName": "ospf_distance_inter_area"
                        },
                        "intra-area": {
                            "vipObjectType": "object",
                            "vipType": "ignore",
                            "vipValue": 110,
                            "vipVariableName": "ospf_distance_intra_area"
                        }
                    },
                    "timers": {
                        "spf": {
                            "delay": {
                                "vipObjectType": "object",
                                "vipType": "ignore",
                                "vipValue": 200,
                                "vipVariableName": "ospf_delay"
                            },
                            "initial-hold": {
                                "vipObjectType": "object",
                                "vipType": "ignore",
                                "vipValue": 1000,
                                "vipVariableName": "ospf_initial_hold"
                            },
                            "max-hold": {
                                "vipObjectType": "object",
                                "vipType": "ignore",
                                "vipValue": 10000,
                                "vipVariableName": "ospf_max_hold"
                            }
                        }
                    },
                    "redistribute": {
                        "vipType": "constant",
                        "vipValue": redis_protocol,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                            "protocol"
                        ]
                    },
                    "max-metric": {
                        "router-lsa": {
                            "vipType": "ignore",
                            "vipValue": [],
                            "vipObjectType": "tree",
                            "vipPrimaryKey": [
                                "ad-type"
                            ]
                        }
                    }
                }
            }
        }

    def to_json(self):
        return self.ospf


# SNMPv2 Feature Template
class TrapServer:
    def __init__(self, server, vpn, port, interface, community, group):
        self.trap_server = {
            "vpn-id": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn),
                "vipVariableName": "snmp_trap_vpn_id"
            },
            "ip": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": server,
                "vipVariableName": "snmp_trap_ip"
            },
            "port": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(port),
                "vipVariableName": "snmp_trap_port"
            },
            "group-name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": group,
                "vipVariableName": "snmp_trap_trap_group_name"
            },
            "community-name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": community,
                "vipVariableName": "snmp_trap_community_name",
                "vipNeedsEncryption": "true"
            },
            "user": {},
            "source-interface": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": interface,
                "vipVariableName": "snmp_trap_source_interface"
            },
            "users": {
                "vipObjectType": "object",
                "vipType": "constant"
            },
            "priority-order": [
                "vpn-id",
                "ip",
                "port",
                "group-name",
                "community-name",
                "source-interface"
            ]
        }

    def to_json(self):
        return self.trap_server


class TrapModule:
    def __init__(self, module, severity):
        self.trap_module = {
            "module": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": module,
                "vipVariableName": "snmp_trap_types_module_0"
            },
            "level": {
                "vipType": "constant",
                "vipValue": [
                    severity
                ],
                "vipObjectType": "list",
                "vipVariableName": "snmp_trap_types_level_0"
            },
            "priority-order": [
                "module",
                "level"
            ]
        }

    def to_json(self):
        return self.trap_module


class Snmpv2Template:
    def __init__(self, name, description, device_type, device_model, view, oid, community, trap_group, trap_module, trap_server):
        self.snmpv2 = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "snmp",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "shutdown": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": "false",
                    "vipVariableName": "snmp_shutdown"
                },
                "contact": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_contact"
                },
                "name": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_device_name"
                },
                "location": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_device_location"
                },
                "view": {
                    "vipType": "constant",
                    "vipValue": [
                        {
                            "name": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": view
                            },
                            "oid": {
                                "vipType": "constant",
                                "vipValue": [
                                    {
                                        "id": {
                                            "vipObjectType": "object",
                                            "vipType": "constant",
                                            "vipValue": oid,
                                            "vipVariableName": "snmp_view_id_0"
                                        },
                                        "exclude": {
                                            "vipObjectType": "node-only",
                                            "vipType": "ignore",
                                            "vipValue": "false",
                                            "vipVariableName": "snmp_view_exclude_0"
                                        },
                                        "priority-order": [
                                            "id",
                                            "exclude"
                                        ]
                                    }
                                ],
                                "vipObjectType": "tree",
                                "vipPrimaryKey": [
                                    "id"
                                ]
                            },
                            "priority-order": [
                                "name",
                                "oid"
                            ]
                        }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name"
                    ]
                },
                "community": {
                    "vipType": "constant",
                    "vipValue": [
                        {
                            "name": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": community,
                                "vipNeedsEncryption": "true"
                            },
                            "view": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": view,
                                "vipVariableName": "snmp_community_view"
                            },
                            "authorization": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": "read-only",
                                "vipVariableName": "snmp_community_authorization"
                            },
                            "priority-order": [
                                "name",
                                "authorization",
                                "view"
                            ]
                        }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name"
                    ]
                },
                "trap": {
                    "group": {
                        "vipType": "constant",
                        "vipValue": [
                            {
                                "group-name": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": trap_group
                                },
                                "enable": {
                                    "vipType": "constant",
                                    "vipValue": trap_module,
                                    "vipObjectType": "tree",
                                    "vipPrimaryKey": [
                                        "module"
                                    ]
                                },
                                "priority-order": [
                                    "group-name",
                                    "enable"
                                ]
                            }
                        ],
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                            "group-name"
                        ]
                    },
                    "target": {
                        "vipType": "constant",
                        "vipValue": trap_server,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                            "vpn-id",
                            "ip",
                            "port"
                        ]
                    }
                }
            }
        }

    def to_json(self):
        return self.snmpv2


# SNMPv3 Feature Template
class TrapServerV3:
    def __init__(self, server, vpn, port, interface, group, user):
        self.trap_server_v3 = {
            "vpn-id": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(vpn),
                "vipVariableName": "snmp_trapv3_vpn_id"
            },
            "ip": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": server,
                "vipVariableName": "snmp_trapv3_ip"
            },
            "port": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": int(port),
                "vipVariableName": "snmp_trapv3_port"
            },
            "group-name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": group,
                "vipVariableName": "snmp_trapv3_trap_group_name"
            },
            "community-name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": "_blank",
                "vipNeedsEncryption": "true"
            },
            "user": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": user,
                "vipVariableName": "snmp_trapv3_user"
            },
            "source-interface": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": interface,
                "vipVariableName": "snmp_trapv3_source_interface"
            },
            "users": {
                "vipObjectType": "object",
                "vipType": "constant"
            },
            "priority-order": [
                "vpn-id",
                "ip",
                "port",
                "group-name",
                "user",
                "source-interface"
            ]
        }


    def to_json(self):
        return self.trap_server_v3


class TrapModuleV3:
    def __init__(self, module, severity):
        self.trap_module_v3 = {
            "module": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": module,
                "vipVariableName": "snmp_trap_types_module_0"
            },
            "level": {
                "vipType": "constant",
                "vipValue": [
                    severity
                ],
                "vipObjectType": "list",
                "vipVariableName": "snmp_trap_types_level_0"
            },
            "priority-order": [
                "module",
                "level"
            ]
        }

    def to_json(self):
        return self.trap_module_v3


class SnmpUser:
    def __init__(self, user, auth, auth_password, priv, priv_password, group):
        self.snmp_user = {
            "name": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": user
            },
            "auth": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": auth,
                "vipVariableName": "snmp_user_auth"
            },
            "auth-password": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": auth_password,
                "vipVariableName": "snmp_user_auth_password"
            },
            "priv": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": priv,
                "vipVariableName": "snmp_user_priv"
            },
            "priv-password": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": priv_password,
                "vipVariableName": "snmp_user_priv_password"
            },
            "group": {
                "vipObjectType": "object",
                "vipType": "constant",
                "vipValue": group,
                "vipVariableName": "snmp_user_group"
            },
            "priority-order": [
                "name",
                "auth",
                "auth-password",
                "priv",
                "priv-password",
                "group"
            ]
        }

    def to_json(self):
        return self.snmp_user


class Snmpv3Template:
    def __init__(self, name, description, device_type, device_model, trap_group, view, oid, group, sec_level, snmp_user, trap_module, trap_server):
        self.snmpv3 = {
            "deviceType": device_type,
            "deviceModels": device_model,
            "feature": "vmanage-default",
            "factoryDefault": False,
            "templateName": name,
            "templateDescription": description,
            "templateType": "snmp",
            "templateMinVersion": template_version,
            "templateDefinition": {
                "shutdown": {
                    "vipObjectType": "object",
                    "vipType": "constant",
                    "vipValue": "false",
                    "vipVariableName": "snmp_shutdown"
                },
                "contact": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_contact"
                },
                "name": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_device_name"
                },
                "location": {
                    "vipObjectType": "object",
                    "vipType": "ignore",
                    "vipVariableName": "snmp_device_location"
                },
                "view": {
                    "vipType": "constant",
                    "vipValue": [
                        {
                            "name": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": view
                            },
                            "oid": {
                                "vipType": "constant",
                                "vipValue": [
                                    {
                                        "id": {
                                            "vipObjectType": "object",
                                            "vipType": "constant",
                                            "vipValue": oid,
                                            "vipVariableName": "snmp_view_id_0"
                                        },
                                        "exclude": {
                                            "vipObjectType": "node-only",
                                            "vipType": "ignore",
                                            "vipValue": "false",
                                            "vipVariableName": "snmp_view_exclude_0"
                                        },
                                        "priority-order": [
                                            "id",
                                            "exclude"
                                        ]
                                    }
                                ],
                                "vipObjectType": "tree",
                                "vipPrimaryKey": [
                                    "id"
                                ]
                            },
                            "priority-order": [
                                "name",
                                "oid"
                            ]
                        }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name"
                    ]
                },
                "group": {
                    "vipType": "constant",
                    "vipValue": [
                        {
                            "name": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": group
                            },
                            "security-level": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": sec_level
                            },
                            "view": {
                                "vipObjectType": "object",
                                "vipType": "constant",
                                "vipValue": view,
                                "vipVariableName": "snmp_group_view"
                            },
                            "priority-order": [
                                "name",
                                "security-level",
                                "view"
                            ]
                        }
                    ],
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name",
                        "security-level"
                    ]
                },
                "user": {
                    "vipType": "constant",
                    "vipValue": snmp_user,
                    "vipObjectType": "tree",
                    "vipPrimaryKey": [
                        "name"
                    ]
                },
                "trap": {
                    "group": {
                        "vipType": "constant",
                        "vipValue": [
                            {
                                "group-name": {
                                    "vipObjectType": "object",
                                    "vipType": "constant",
                                    "vipValue": trap_group
                                },
                                "enable": {
                                    "vipType": "constant",
                                    "vipValue": trap_module,
                                    "vipObjectType": "tree",
                                    "vipPrimaryKey": [
                                        "module"
                                    ]
                                },
                                "priority-order": [
                                    "group-name",
                                    "enable"
                                ]
                            }
                        ],
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                            "group-name"
                        ]
                    },
                    "target": {
                        "vipType": "constant",
                        "vipValue": trap_server,
                        "vipObjectType": "tree",
                        "vipPrimaryKey": [
                            "vpn-id",
                            "ip",
                            "port"
                        ]
                    }
                }
            }
        }

    def to_json(self):
        return self.snmpv3




# ------------------------------------------------------------------------------------------------------ #
# Modify Feature Templates
# Add OSPF Area and Interfaces to OSPF Templates

class OspfInterface:
    def __init__(self, interface, vip_type='ignore', auth_type='', auth_key='', md_key_id='', md_key=''):
        self.ospf_interface = {
            "name": {
                "originalDefaultOption": "constant",
                "dataPath": [],
                "vipObjectType": "object",
                "vipType": "constant",
                "vipVariableName": "ospf_name",
                "vipValue": interface
            },
            "hello-interval": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipValue": 10,
                "vipType": "ignore",
                "vipVariableName": "ospf_hello_interval"
            },
            "dead-interval": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipValue": 40,
                "vipType": "ignore",
                "vipVariableName": "ospf_dead_interval"
            },
            "retransmit-interval": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipValue": 5,
                "vipType": "ignore",
                "vipVariableName": "ospf_retransmit_interval"
            },
            "cost": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipType": "ignore",
                "vipVariableName": "ospf_cost"
            },
            "priority": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipValue": 1,
                "vipType": "ignore",
                "vipVariableName": "ospf_priority"
            },
            "network": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "object",
                "vipValue": "broadcast",
                "vipType": "ignore",
                "vipVariableName": "ospf_network"
            },
            "passive-interface": {
                "originalDefaultOption": "ignore",
                "dataPath": [],
                "vipObjectType": "node-only",
                "vipValue": "false",
                "vipType": "ignore",
                "vipVariableName": "ospf_passive_interface"
            },
            "authentication": {
                "type": {
                    "vipObjectType": "object",
                    "vipType": vip_type,
                    "vipValue": auth_type,
                    "vipVariableName": "ospf_authentication_type"
                },
                "authentication-key": {
                    "vipObjectType": "object",
                    "vipType": vip_type,
                    "vipValue": auth_key,
                    "vipVariableName": "ospf_authentication_key"
                },
                "message-digest": {
                    "message-digest-key": {
                        "vipObjectType": "object",
                        "vipType": vip_type,
                        "vipValue": md_key_id,
                        "vipVariableName": "ospf_message_digest_key"
                    },
                    "md5": {
                        "vipObjectType": "object",
                        "vipType": vip_type,
                        "vipValue": md_key,
                        "vipVariableName": "ospf_md5"
                    }
                }
            },
            "priority-order": [
                "name",
                "hello-interval",
                "dead-interval",
                "retransmit-interval",
                "cost",
                "priority",
                "network",
                "passive-interface",
                "authentication"
            ]
        }

    def to_json(self):
        return self.ospf_interface
        

#ASA20211130 - Added by Santi - add logic to loop when modify the ospf interface template - BGN ----
class OspfAreaANumM:
    def __init__(self, ospf_areanumd):
        self.ospf_area_anumm = {
            "vipType": "constant",
            "vipValue": ospf_areanumd,
            "vipObjectType": "tree",
            "vipPrimaryKey": [
                "a-num"
            ]
        }
      
    def to_json(self):
        return self.ospf_area_anumm


class OspfAreaANumD:
    def __init__(self, vipval, ospf_int):
        self.ospf_area_anumd = {
            "a-num": 
                {
                    "originalDefaultOption": "constant",
                    "dataPath": [],
                    "vipObjectType": "object",
                    "vipValue": vipval,
                    "vipType": "constant",
                    "vipVariableName": "ospf_area_a_num"
                },
            "stub": 
                {
                    "no-summary": 
                    {
                        "vipType": "ignore","vipObjectType": "node-only"
                    }
                },
            "nssa": 
                {
                    "no-summary": 
                    {
                        "vipType": "ignore",
                        "vipObjectType": "node-only"
                    },
                    "translate": 
                    {
                        "vipType": "ignore",
                        "vipObjectType": "object"
                    }
                },
            "interface": 
                {
                    "vipType": "constant",
                    "vipValue": ospf_int,
                    "vipObjectType": "tree",
                    "vipPrimaryKey": ["name"]
                },
            "priority-order": ["a-num","interface"]
        }

    def to_json(self):
        return self.ospf_area_anumd
#ASA20211130 - Added by Santi - add logic to loop when modify the ospf interface template - END ----
