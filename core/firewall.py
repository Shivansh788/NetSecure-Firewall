# core/firewall.py

import logging
import time
import random
from scapy.all import sniff, IP, TCP, UDP

from core.rule_engine import match_rule
from core.ids import detect
from core.behavior_monitor import monitor_traffic, is_rate_limited
from core.dpi import inspect

from core.ai_analyzer import analyze_with_ai
from core.ai_parser import parse_ai_response
from core.ai_agent import generate_rule_from_ai

# =========================================
# CONFIG
# =========================================

logging.basicConfig(
    filename="logs/events.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

BLOCK_THRESHOLD = 5
TEMP_BLOCK_DURATION = 60

THREAT_SCORES = {}
BLOCKED_IPS = {}
SESSION_TABLE = {}
IP_ATTACK_HISTORY = {}

# =========================================
# GEO + WHITELIST
# =========================================

GEO_BLOCKED = ["10.", "172.16."]
WHITELIST = ["127.0.0.1"]


def is_geo_blocked(ip):
    return any(ip.startswith(p) for p in GEO_BLOCKED)


def is_whitelisted(ip):
    return ip in WHITELIST


# =========================================
# IPS ENGINE
# =========================================

def increase_threat_score(ip, amount, reason=None):
    THREAT_SCORES[ip] = THREAT_SCORES.get(ip, 0) + amount

    if THREAT_SCORES[ip] >= BLOCK_THRESHOLD:
        block_ip(ip, reason)


def block_ip(ip, reason=None):
    BLOCKED_IPS[ip] = {
        "time": time.time(),
        "reason": reason,
    }
    logging.critical(f"[BLOCKED] {ip} | Reason: {reason}")


def is_blocked(ip):
    if ip not in BLOCKED_IPS:
        return False

    if time.time() - BLOCKED_IPS[ip]["time"] > TEMP_BLOCK_DURATION:
        del BLOCKED_IPS[ip]
        logging.info(f"[UNBLOCKED] {ip}")
        return False

    return True


# =========================================
# SESSION TRACKING
# =========================================

def update_session(src, dst, port):
    key = (src, dst, port)
    SESSION_TABLE[key] = SESSION_TABLE.get(key, "NEW")


# =========================================
# ATTACK HISTORY
# =========================================

def record_attack(ip, attack):
    if ip not in IP_ATTACK_HISTORY:
        IP_ATTACK_HISTORY[ip] = []
    IP_ATTACK_HISTORY[ip].append(attack)


# =========================================
# AI DECISION + AGENT
# =========================================

def ai_decision(payload, src_ip):
    ai_raw = analyze_with_ai(payload)
    ai_result = parse_ai_response(ai_raw)

    logging.warning(f"[AI] {ai_result}")

    severity = ai_result.get("severity", "LOW")
    confidence = int(ai_result.get("confidence", 50))

    # 🔥 Agent creates rules
    agent_msg = generate_rule_from_ai(ai_result, src_ip)
    logging.info(agent_msg)

    # 🔥 Explainable AI log
    logging.info(
        f"[AI EXPLAIN] IP={src_ip} | "
        f"Attack={ai_result.get('attack_type')} | "
        f"Confidence={confidence} | "
        f"Reason={ai_result.get('reason')}"
    )

    # 🔥 Decision layer
    if severity == "HIGH" and confidence >= 80:
        block_ip(src_ip, "AI_HIGH_CONFIDENCE")

    elif severity == "HIGH":
        increase_threat_score(src_ip, 3, "AI_HIGH")

    elif severity == "MEDIUM":
        increase_threat_score(src_ip, 2, "AI_MEDIUM")

    else:
        increase_threat_score(src_ip, 1, "AI_LOW")


# =========================================
# THREAT LEVEL
# =========================================

def get_threat_level(ip):
    score = THREAT_SCORES.get(ip, 0)

    if score >= 7:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    return "LOW"


# =========================================
# CORE PACKET PROCESSING
# =========================================

def process_packet_data(src_ip, dst_ip, protocol, port, payload="", tcp_flags=None):

    # 0️⃣ WHITELIST
    if is_whitelisted(src_ip):
        logging.info(f"[WHITELIST] {src_ip}")
        return

    # 1️⃣ GEO BLOCK
    if is_geo_blocked(src_ip):
        logging.critical(f"[GEO BLOCK] {src_ip}")
        return

    # 2️⃣ BLOCK CHECK
    if is_blocked(src_ip):
        logging.warning(f"[BLOCKED TRAFFIC] {src_ip}")
        return

    update_session(src_ip, dst_ip, port)

    # ---------------------------
    # 3️⃣ RATE LIMIT
    # ---------------------------
    if is_rate_limited(src_ip):
        logging.warning(f"[RATE LIMIT] {src_ip}")
        increase_threat_score(src_ip, 3, "RATE_LIMIT")

    # ---------------------------
    # 4️⃣ IDS
    # ---------------------------
    ids_alert = detect(src_ip, port, payload, tcp_flags)

    if ids_alert:
        logging.warning(f"[IDS] {ids_alert} from {src_ip}")
        record_attack(src_ip, ids_alert)
        increase_threat_score(src_ip, 2, ids_alert)

    # ---------------------------
    # 5️⃣ DPI
    # ---------------------------
    dpi_alert = inspect(payload)

    if dpi_alert:
        logging.warning(f"[DPI] {dpi_alert} from {src_ip}")
        record_attack(src_ip, dpi_alert)
        increase_threat_score(src_ip, 3, dpi_alert)

        # 🔥 AI layer
        ai_decision(payload, src_ip)

    # ---------------------------
    # 6️⃣ BEHAVIOR
    # ---------------------------
    behavior_alert = monitor_traffic(src_ip, port, payload)

    if behavior_alert:
        logging.warning(f"[BEHAVIOR] {behavior_alert} from {src_ip}")
        increase_threat_score(src_ip, 1, behavior_alert)

    # ---------------------------
    # 7️⃣ FIREWALL RULE ENGINE
    # ---------------------------
    action = match_rule(src_ip, dst_ip, protocol, port)

    if action == "DROP":
        logging.warning(f"[DROP] {src_ip} → {dst_ip}")
        increase_threat_score(src_ip, 3, "POLICY")
        return

    logging.info(f"[ALLOW] {src_ip} → {dst_ip}")

    # ---------------------------
    # FINAL THREAT LEVEL
    # ---------------------------
    level = get_threat_level(src_ip)
    logging.info(f"[THREAT LEVEL] {src_ip} → {level}")


# =========================================
# REAL MODE
# =========================================

def process_real_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = None
        port = None
        payload = ""
        tcp_flags = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport
            tcp_flags = packet[TCP].flags

        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        if hasattr(packet, "load"):
            try:
                payload = packet.load.decode(errors="ignore")
            except:
                payload = str(packet.load)

        if protocol and port:
            process_packet_data(src_ip, dst_ip, protocol, port, payload, tcp_flags)


# =========================================
# SIMULATION
# =========================================

def run_simulation():

    print("⚡ Simulation Mode Started")

    test_ips = ["192.168.1.10", "192.168.1.20"]
    dst_ip = "192.168.1.1"

    payloads = [
        "normal",
        "SELECT * FROM users WHERE id=1 OR 1=1",
        "<script>alert('xss')</script>",
        "../etc/passwd",
        "A" * 5000
    ]

    while True:
        process_packet_data(
            random.choice(test_ips),
            dst_ip,
            "TCP",
            random.choice([80, 443]),
            random.choice(payloads)
        )
        time.sleep(2)


# =========================================
# START
# =========================================

def start_firewall(mode="sim"):
    print("🔥 NetSecure AI Firewall Started")

    if mode == "real":
        sniff(prn=process_real_packet, store=0)
    else:
        run_simulation()
