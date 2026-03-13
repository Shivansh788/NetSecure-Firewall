import logging
import time
import random
from scapy.all import sniff, IP, TCP, UDP

from core.rule_engine import match_rule
from core.ids import detect, block_ip, is_blocked
from core.behavior_monitor import monitor_traffic
from core.dpi import inspect

# =========================================
# GEO BLOCKING SIMULATION
# =========================================

GEO_BLOCKED_RANGES = [
    "10.",  # Example simulated country
    "172.16.",  # Example simulated country
]


def is_geo_blocked(ip):
    for prefix in GEO_BLOCKED_RANGES:
        if ip.startswith(prefix):
            return True
    return False


# =========================================
# LOGGING CONFIGURATION
# =========================================

logging.basicConfig(
    filename="logs/events.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# =========================================
# IPS THREAT SCORING ENGINE
# =========================================
ATTACK_STATS = {}
PACKET_COUNT = 0
# =========================================
# ENHANCED IPS ENGINE
# =========================================

THREAT_SCORES = {}
BLOCKED_IPS = {}

BLOCK_THRESHOLD = 5
TEMP_BLOCK_DURATION = 60  # seconds


def increase_threat_score(ip, amount, attack_type=None):

    THREAT_SCORES[ip] = THREAT_SCORES.get(ip, 0) + amount

    # Severe attacks → permanent block
    if attack_type in ["RCE_ATTEMPT", "DATA_EXFILTRATION"]:
        block_ip(ip, permanent=True, reason=attack_type)
        return

    if THREAT_SCORES[ip] >= BLOCK_THRESHOLD:
        block_ip(
            ip,
            src_ip=ip,
            dst_ip="TARGET_SERVER",
            port="UNKNOWN",
            permanent=False,
            reason=attack_type,
        )


def block_ip(ip, src_ip=None, dst_ip=None, port=None, permanent=False, reason=None):

    BLOCKED_IPS[ip] = {
        "blocked_at": time.time(),
        "permanent": permanent,
        "reason": reason,
    }

    if permanent:
        logging.critical(f"[IPS] PERMANENT BLOCK: {ip} | Reason: {reason}")
    else:
        logging.critical(f"[IPS] TEMP BLOCK: {ip} | Reason: {reason}")

    # Simulate connection reset if connection info available
    if src_ip and dst_ip and port:
        reset_connection(src_ip, dst_ip, port)


def reset_connection(src_ip, dst_ip, port):
    logging.warning(f"[IPS] CONNECTION RESET sent to {src_ip} → {dst_ip} | Port {port}")


def is_blocked(ip):

    if ip not in BLOCKED_IPS:
        return False

    block_info = BLOCKED_IPS[ip]

    if block_info["permanent"]:
        return True

    # Auto-unblock after timeout
    if time.time() - block_info["blocked_at"] > TEMP_BLOCK_DURATION:
        del BLOCKED_IPS[ip]
        logging.info(f"[IPS] AUTO-UNBLOCKED {ip}")
        return False

    return True


# =========================================
# BASIC STATEFUL SESSION TABLE
# =========================================

SESSION_TABLE = {}


def update_session(src_ip, dst_ip, port):
    session_key = (src_ip, dst_ip, port)

    if session_key not in SESSION_TABLE:
        SESSION_TABLE[session_key] = "NEW"
    else:
        SESSION_TABLE[session_key] = "ESTABLISHED"


# =========================================
# CORE PACKET PROCESSING
# =========================================


def process_packet_data(src_ip, dst_ip, protocol, port, payload="", tcp_flags=None):
    global PACKET_COUNT
    PACKET_COUNT += 1

    # Geo-block check
    if is_geo_blocked(src_ip):
        logging.critical(f"[GEO BLOCK] Traffic blocked from {src_ip}")
        return

    # Already blocked
    if is_blocked(src_ip):
        logging.warning(f"[BLOCKED TRAFFIC] from {src_ip}")
        return

    # Update session (stateful)
    update_session(src_ip, dst_ip, port)

    # ---------------------------
    # 1️⃣ IDS Detection FIRST
    # ---------------------------
    ids_alert = detect(src_ip, port, payload, tcp_flags)

    if ids_alert:
        logging.warning(f"[IDS ALERT] {ids_alert} from {src_ip}")
        ATTACK_STATS[ids_alert] = ATTACK_STATS.get(ids_alert, 0) + 1
        increase_threat_score(src_ip, 2, ids_alert)

    # ---------------------------
    # 2️⃣ DPI Detection SECOND
    # ---------------------------
    dpi_alert = inspect(payload)

    if dpi_alert:
        logging.warning(f"[DPI ALERT] {dpi_alert} from {src_ip}")
        ATTACK_STATS[dpi_alert] = ATTACK_STATS.get(dpi_alert, 0) + 1
        increase_threat_score(src_ip, 3, dpi_alert)

    # ---------------------------
    # 3️⃣ Behavioral Monitoring
    # ---------------------------
    anomaly = monitor_traffic(src_ip)

    if anomaly:
        logging.warning(f"[ANOMALY DETECTED] from {src_ip}")
        increase_threat_score(src_ip, 1)

    # ---------------------------
    # 4️⃣ THEN Firewall Rule Engine
    # ---------------------------
    action = match_rule(src_ip, dst_ip, protocol, port)

    if action == "DROP":
        logging.warning(f"[FIREWALL DROP] {src_ip} → {dst_ip} | Port {port}")
        increase_threat_score(src_ip, 3, "FIREWALL_POLICY_VIOLATION")
        return

    logging.info(f"[ALLOWED] {src_ip} → {dst_ip} | Port {port}")


# =========================================
# REAL PACKET MODE (Linux)
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
# SIMULATION MODE (Windows Safe)
# =========================================


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
        "SELECT * FROM users WHERE id=1 OR 1=1",
        "<script>alert('xss')</script>",
        "../etc/passwd",
        "login login login login login",
        "A" * 6000,  # simulate data exfiltration
    ]

    while True:

        src_ip = random.choice(test_ips)
        port = random.choice([22, 80, 443])
        payload = random.choice(test_payloads)

        # Simulate TCP flags
        tcp_flags = random.choice(["S", None, None, None])

        process_packet_data(src_ip, dst_ip, "TCP", port, payload, tcp_flags)

        time.sleep(2)


# =========================================
# FIREWALL STARTER
# =========================================


def start_firewall(mode="sim"):

    print("🔥 NetSecure Advanced NGFW Started")

    if mode == "real":
        print("🟢 Running in Real Packet Mode")
        sniff(prn=process_real_packet, store=0)
    else:
        run_simulation()
