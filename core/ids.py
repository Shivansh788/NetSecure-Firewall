import time
from collections import defaultdict

# ===========================
# TRACKING STRUCTURES
# ===========================

port_history = defaultdict(list)
request_history = defaultdict(list)
syn_history = defaultdict(list)
payload_volume = defaultdict(int)

TIME_WINDOW = 10  # seconds

PORT_SCAN_THRESHOLD = 15
DOS_THRESHOLD = 40
SYN_FLOOD_THRESHOLD = 3
DATA_EXFIL_THRESHOLD = 5000  # bytes


# ===========================
# PORT SCAN DETECTION
# ===========================


def detect_port_scan(src_ip, port):
    now = time.time()
    port_history[src_ip].append((port, now))

    recent_ports = [p for p, t in port_history[src_ip] if now - t <= TIME_WINDOW]

    if len(set(recent_ports)) > PORT_SCAN_THRESHOLD:
        return "PORT_SCAN"

    return None


# ===========================
# DOS / UDP / ICMP FLOOD
# ===========================


def detect_dos(src_ip):
    now = time.time()
    request_history[src_ip].append(now)

    recent_requests = [t for t in request_history[src_ip] if now - t <= TIME_WINDOW]

    if len(recent_requests) > DOS_THRESHOLD:
        return "DOS_ATTACK"

    return None


# ===========================
# SYN FLOOD DETECTION
# ===========================


def detect_syn_flood(src_ip, tcp_flags):
    # print("BEFORE APPEND:", syn_history[src_ip])
    # print("AFTER APPEND:", syn_history[src_ip])
    now = time.time()

    # print("TCP FLAGS:", tcp_flags)

    # Add SYN packet to history
    if tcp_flags and "S" in str(tcp_flags):
        syn_history[src_ip].append(now)

    # Keep only packets within time window
    recent_syn = [t for t in syn_history[src_ip] if now - t <= TIME_WINDOW]

    # print("SYN COUNT:", len(recent_syn))

    if len(recent_syn) >= SYN_FLOOD_THRESHOLD:
        return "SYN_FLOOD"

    return None


# ===========================
# NULL / XMAS SCAN
# ===========================


def detect_null_xmas_scan(tcp_flags):
    if tcp_flags == 0:
        return "NULL_SCAN"

    if str(tcp_flags) == "FPU":
        return "XMAS_SCAN"

    return None


# ===========================
# DATA EXFILTRATION
# ===========================


def detect_data_exfil(src_ip, payload):
    if payload:
        payload_volume[src_ip] += len(payload.encode())

    if payload_volume[src_ip] > DATA_EXFIL_THRESHOLD:
        return "DATA_EXFILTRATION"

    return None


# ===========================
# MASTER IDS DETECT
# ===========================


def detect(src_ip, port, payload, tcp_flags=None):

    return (
        detect_port_scan(src_ip, port)
        or detect_dos(src_ip)
        or detect_syn_flood(src_ip, tcp_flags)
        or detect_null_xmas_scan(tcp_flags)
        or detect_data_exfil(src_ip, payload)
    )


# ===========================
# IPS SUPPORT FUNCTIONS
# ===========================

blocked_ips = set()


def block_ip(ip):
    blocked_ips.add(ip)


def is_blocked(ip):
    return ip in blocked_ips
