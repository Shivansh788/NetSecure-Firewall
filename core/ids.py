from collections import defaultdict
import time

connection_tracker = defaultdict(list)
blocked_ips = set()

PORT_SCAN_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW = 10


def detect_port_scan(src_ip, port):
    now = time.time()
    connection_tracker[src_ip].append((port, now))

    recent = [p for p, t in connection_tracker[src_ip] if now - t < TIME_WINDOW]
    if len(set(recent)) > PORT_SCAN_THRESHOLD:
        return "PORT_SCAN"
    return None


def detect_bruteforce(src_ip):
    now = time.time()
    connection_tracker[src_ip].append(("LOGIN", now))

    recent = [p for p, t in connection_tracker[src_ip] if now - t < TIME_WINDOW]
    if recent.count("LOGIN") > BRUTE_FORCE_THRESHOLD:
        return "BRUTE_FORCE"
    return None


def block_ip(src_ip):
    blocked_ips.add(src_ip)


def is_blocked(src_ip):
    return src_ip in blocked_ips