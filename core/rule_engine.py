import ipaddress

ZONES = {
    "PUBLIC": ipaddress.IPv4Network("192.168.10.0/24"),
    "INTERNAL": ipaddress.IPv4Network("192.168.20.0/24"),
    "RESTRICTED": ipaddress.IPv4Network("192.168.20.100/32")
}

FIREWALL_RULES = [
    {"source_zone": "PUBLIC", "dest_zone": "INTERNAL", "protocol": "TCP", "port": 22, "action": "DROP"},
    {"source_zone": "INTERNAL", "dest_zone": "PUBLIC", "protocol": "TCP", "port": 80, "action": "ALLOW"},
]


def get_zone(ip):
    ip_obj = ipaddress.IPv4Address(ip)
    for zone, network in ZONES.items():
        if ip_obj in network:
            return zone
    return "UNKNOWN"


def match_rule(src_ip, dst_ip, protocol, port):
    src_zone = get_zone(src_ip)
    dst_zone = get_zone(dst_ip)

    for rule in FIREWALL_RULES:
        if (
            rule["source_zone"] == src_zone and
            rule["dest_zone"] == dst_zone and
            rule["protocol"] == protocol and
            rule["port"] == port
        ):
            return rule["action"]

    return "ALLOW"