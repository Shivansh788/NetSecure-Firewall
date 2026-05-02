# core/behavior_monitor.py

from collections import defaultdict, deque
import time

# =========================================
# CONFIG
# =========================================

WINDOW = 10              # seconds for rate checks
RATE_LIMIT = 20          # requests per window
BURST_LIMIT = 10         # requests in short burst
SLOW_ATTACK_WINDOW = 60  # seconds
SLOW_ATTACK_LIMIT = 50

PORT_SCAN_THRESHOLD = 10
PAYLOAD_SIZE_THRESHOLD = 4000

# =========================================
# DATA STRUCTURES
# =========================================

REQUEST_LOG = defaultdict(deque)
PORT_ACCESS_LOG = defaultdict(set)
PAYLOAD_LOG = defaultdict(list)
FIRST_SEEN = {}
LAST_SEEN = {}
IP_SCORE = defaultdict(int)

# =========================================
# RATE LIMITING
# =========================================

def is_rate_limited(ip):
    now = time.time()
    log = REQUEST_LOG[ip]

    # remove old entries
    while log and now - log[0] > WINDOW:
        log.popleft()

    log.append(now)

    return len(log) > RATE_LIMIT


# =========================================
# BURST DETECTION (very fast requests)
# =========================================

def detect_burst(ip):
    log = REQUEST_LOG[ip]

    if len(log) >= BURST_LIMIT:
        if log[-1] - log[-BURST_LIMIT] < 1:  # burst within 1 sec
            return True

    return False


# =========================================
# SLOW ATTACK DETECTION
# =========================================

SLOW_LOG = defaultdict(deque)

def detect_slow_attack(ip):
    now = time.time()
    log = SLOW_LOG[ip]

    while log and now - log[0] > SLOW_ATTACK_WINDOW:
        log.popleft()

    log.append(now)

    return len(log) > SLOW_ATTACK_LIMIT


# =========================================
# PORT SCAN DETECTION
# =========================================

def detect_port_scan(ip, port):
    ports = PORT_ACCESS_LOG[ip]
    ports.add(port)

    if len(ports) > PORT_SCAN_THRESHOLD:
        return True

    return False


# =========================================
# PAYLOAD SIZE ANOMALY
# =========================================

def detect_payload_anomaly(ip, payload):
    size = len(payload)
    PAYLOAD_LOG[ip].append(size)

    if size > PAYLOAD_SIZE_THRESHOLD:
        return True

    return False


# =========================================
# SESSION TIMING (suspicious frequency)
# =========================================

def update_timestamps(ip):
    now = time.time()

    if ip not in FIRST_SEEN:
        FIRST_SEEN[ip] = now

    LAST_SEEN[ip] = now


def detect_fast_reconnect(ip):
    if ip not in FIRST_SEEN:
        return False

    if LAST_SEEN[ip] - FIRST_SEEN[ip] < 1:
        return True

    return False


# =========================================
# BEHAVIOR SCORE SYSTEM
# =========================================

def increase_ip_score(ip, amount):
    IP_SCORE[ip] += amount


def get_ip_score(ip):
    return IP_SCORE[ip]


# =========================================
# MAIN BEHAVIOR MONITOR
# =========================================

def monitor_traffic(src_ip, port=None, payload=""):
    """
    Returns:
    - None if normal
    - string describing anomaly
    """

    update_timestamps(src_ip)

    # 🔥 rate limiting
    if is_rate_limited(src_ip):
        increase_ip_score(src_ip, 2)
        return "RATE_LIMIT_EXCEEDED"

    # 🔥 burst detection
    if detect_burst(src_ip):
        increase_ip_score(src_ip, 2)
        return "BURST_TRAFFIC"

    # 🔥 slow attack
    if detect_slow_attack(src_ip):
        increase_ip_score(src_ip, 2)
        return "SLOW_ATTACK"

    # 🔥 port scanning
    if port and detect_port_scan(src_ip, port):
        increase_ip_score(src_ip, 3)
        return "PORT_SCAN"

    # 🔥 payload anomaly
    if payload and detect_payload_anomaly(src_ip, payload):
        increase_ip_score(src_ip, 3)
        return "LARGE_PAYLOAD"

    # 🔥 reconnect anomaly
    if detect_fast_reconnect(src_ip):
        increase_ip_score(src_ip, 1)
        return "FAST_RECONNECT"

    return None
