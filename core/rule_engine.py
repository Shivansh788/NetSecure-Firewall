# core/rule_engine.py

import logging
import ipaddress
import json
import time
from core.conflict_detector import detect_conflicts

# =========================================
# CONFIG
# =========================================

RULES_FILE = "config/rules.json"

ZONES = {
    "PUBLIC": ipaddress.IPv4Network("192.168.10.0/24"),
    "INTERNAL": ipaddress.IPv4Network("192.168.20.0/24"),
    "RESTRICTED": ipaddress.IPv4Network("192.168.20.100/32"),
}

RULE_CACHE = []
LAST_LOADED = 0
CACHE_TTL = 5


# =========================================
# LOAD RULES (CACHED)
# =========================================

def load_rules():
    global RULE_CACHE, LAST_LOADED

    if time.time() - LAST_LOADED < CACHE_TTL:
        return RULE_CACHE

    try:
        with open(RULES_FILE, "r") as f:
            rules = json.load(f)
    except:
        rules = []

    # 🔥 remove expired rules
    rules = [
        r for r in rules
        if "expires_at" not in r or r["expires_at"] > time.time()
    ]

    # sort by priority
    rules = sorted(rules, key=lambda r: r.get("priority", 100))

    # detect conflicts
    conflicts = detect_conflicts(rules)
    for c in conflicts:
        logging.warning(f"[RULE CONFLICT] {c[0]} vs {c[1]}")

    RULE_CACHE = rules
    LAST_LOADED = time.time()

    return RULE_CACHE


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)


# =========================================
# ZONE DETECTION
# =========================================

def get_zone(ip):
    ip_obj = ipaddress.IPv4Address(ip)

    for zone, network in ZONES.items():
        if ip_obj in network:
            return zone

    return "UNKNOWN"


# =========================================
# MATCH ENGINE
# =========================================

def match_rule(src_ip, dst_ip, protocol, port):

    src_zone = get_zone(src_ip)
    dst_zone = get_zone(dst_ip)

    rules = load_rules()

    for rule in rules:

        if not rule.get("enabled", True):
            continue

        if (
            (rule.get("source_zone") in [src_zone, "ANY"])
            and (rule.get("dest_zone") in [dst_zone, "ANY"])
            and (rule.get("protocol") in [protocol, "ANY"])
            and (rule.get("port") in [port, "ANY"])
        ):
            return rule.get("action", "DROP")

    return "DROP"  # Zero Trust


# =========================================
# RULE MANAGEMENT
# =========================================

def add_rule(rule):
    rules = load_rules()
    rule["id"] = int(time.time() * 1000)

    rules.append(rule)
    save_rules(rules)

    logging.info(f"[RULE ADDED] {rule}")


def remove_rule(rule_id):
    rules = load_rules()
    rules = [r for r in rules if r.get("id") != rule_id]
    save_rules(rules)

    logging.info(f"[RULE REMOVED] {rule_id}")


# =========================================
# 🔥 AI RULE CREATION (CORE FEATURE)
# =========================================

def add_ai_rule(src_ip, action, reason, ttl):

    rules = load_rules()

    # 🔥 Prevent duplicate rules
    for rule in rules:
        if (
            str(rule.get("source")) == str(src_ip)
            and str(rule.get("reason")) == str(reason)
        ):
            return rule  # Already exists

    new_rule = {
        "id": int(time.time() * 1000),
        "source": src_ip,
        "destination": "ANY",

        # 🔥 ADD THESE (FIX CRASH)
        "source_zone": get_zone(src_ip),
        "dest_zone": "ANY",

        "protocol": "ANY",
        "port": "ANY",
        "action": action,
        "reason": reason,
        "enabled": True,
        "created_at": time.time(),
        "ttl": ttl
    }
    

    rules.append(new_rule)
    save_rules(rules)

    return new_rule

def clean_duplicate_rules():
    rules = load_rules()
    seen = set()
    unique = []

    for r in rules:
        if r.get("source"):  
            key = (r.get("source"), r.get("reason"))   # AI rules
        else:
            key = (
                r.get("source_zone"),
                r.get("dest_zone"),
                r.get("protocol"),
                r.get("port")
    )   # Manual rules

        if key not in seen:
            seen.add(key)
            unique.append(r)

    save_rules(unique)
