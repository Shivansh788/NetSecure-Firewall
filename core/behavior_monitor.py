from collections import defaultdict
import time

traffic_stats = defaultdict(int)
THRESHOLD = 100

def monitor_traffic(src_ip):
    traffic_stats[src_ip] += 1
    if traffic_stats[src_ip] > THRESHOLD:
        return "ANOMALOUS_TRAFFIC"
    return None