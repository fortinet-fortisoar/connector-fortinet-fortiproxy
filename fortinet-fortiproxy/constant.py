"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

Policy_Type = {
    "Explicit Web": "explicit-web",
    "Transparent": "transparent",
    "Explicit FTP": "explicit-ftp",
    "SSH Tunnel": "ssh-tunnel",
    "SSH": "ssh",
    "Access Proxy": "access-proxy",
    "WanOpt": "wanopt"
}

WAN_Optimization = {
    "Default": "default",
    "Transparent": "transparent",
    "Non Transparent": "non-transparent"
}

Address_Type = {
    "IP Mask": "ipmask",
    "IP Range": "iprange",
    "FQDN": "fqdn",
    "Geography": "geography",
    "WildCard": "wildcard",
    "Dynamic": "dynamic",
    "Interface Subnet": "interface-subnet",
    "MAC": "mac"
}

Sub_Type_Address = {
    "SDN": "sdn",
    "ClearPass SPT": "clearpass-spt",
    "FSSO": "fsso",
    "EMS Tag": "ems-tag",
    "SWC Tag": "swc-tag"
}
