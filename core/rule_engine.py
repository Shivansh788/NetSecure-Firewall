from core.conflict_detector import detect_conflicts
import logging
import ipaddress
import json


ZONES = {
    "PUBLIC": ipaddress.IPv4Network("192.168.10.0/24"),
    "INTERNAL": ipaddress.IPv4Network("192.168.20.0/24"),
    "RESTRICTED": ipaddress.IPv4Network("192.168.20.100/32"),
}

RULES_FILE = "config/rules.json"


def load_rules():
    with open(RULES_FILE, "r") as f:
        rules = json.load(f)

    rules = sorted(rules, key=lambda r: r["priority"])

    # Detect conflicts
    conflicts = detect_conflicts(rules)

    if conflicts:
        for c in conflicts:
            logging.warning(
                f"[RULE CONFLICT] Rule {c[0]} conflicts with Rule {c[1]}"
            )

    return rules


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)


def get_zone(ip):
    ip_obj = ipaddress.IPv4Address(ip)

    for zone, network in ZONES.items():
        if ip_obj in network:
            return zone

    return "UNKNOWN"


def match_rule(src_ip, dst_ip, protocol, port):

    src_zone = get_zone(src_ip)
    dst_zone = get_zone(dst_ip)

    rules = load_rules()

    for rule in rules:

        if not rule.get("enabled", True):
            continue

        if (
            rule["source_zone"] == src_zone
            and rule["dest_zone"] == dst_zone
            and rule["protocol"] == protocol
            and rule["port"] == port
        ):
            return rule["action"]

    # Zero Trust Default Deny
    return "DROP"


# =========================================
# DYNAMIC RULE MANAGEMENT FUNCTIONS
# =========================================


def add_rule(rule):
    rules = load_rules()
    rules.append(rule)
    save_rules(rules)


def remove_rule(rule_id):
    rules = load_rules()
    rules = [r for r in rules if r["id"] != rule_id]
    save_rules(rules)


def toggle_rule(rule_id, status):
    rules = load_rules()

    for rule in rules:
        if rule["id"] == rule_id:
            rule["enabled"] = status

    save_rules(rules)
