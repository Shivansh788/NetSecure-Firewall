from flask import Flask, render_template, jsonify
import os
import time
import logging
from datetime import datetime

import core.firewall as firewall
from core.rule_engine import load_rules, save_rules



SIM_STATS = {}
SIM_BLOCKED = {}

app = Flask(__name__, template_folder="templates")


def get_recent_logs(lines=100):
    log_file = "logs/events.log"

    if not os.path.exists(log_file):
        return []

    with open(log_file, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        block_size = 1024
        data = b""

        while file_size > 0 and len(data.splitlines()) <= lines:
            seek_size = min(block_size, file_size)
            f.seek(file_size - seek_size)
            data = f.read(seek_size) + data
            file_size -= seek_size

    return data.decode(errors="ignore").splitlines()[-lines:]



@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/unblock/<ip>")
def unblock(ip):
    firewall.BLOCKED_IPS.pop(ip, None)
    return {"status": "ok"}


@app.route("/api/toggle-rule/<int:rule_id>", methods=["POST"])
def toggle_rule(rule_id):
    rules = load_rules()

    for rule in rules:
        if rule["id"] == rule_id:
            rule["enabled"] = not rule.get("enabled", True)

    save_rules(rules)

    return {"status": "ok"}

@app.route("/api/simulate/<attack>")
def simulate_attack(attack):
    mapping = {
        "sql": "SQL_INJECTION",
        "xss": "XSS",
        "path": "PATH_TRAVERSAL",
        "dos": "DDOS"
    }

    attack_type = mapping.get(attack, "BENIGN")
    import random

    src_ip = f"192.168.1.{random.randint(10, 250)}"

    # 🔥 Update stats
    firewall.ATTACK_STATS[attack_type] = firewall.ATTACK_STATS.get(attack_type, 0) + 1

    # 🔥 Log for UI
    logging.warning(f"[SIM] {attack_type} from {src_ip}")

    # 🔥 Simulate block
    firewall.BLOCKED_IPS[src_ip] = {
        "time": time.time(),
        "reason": attack_type
    }
    from core.ai_agent import generate_rule_from_ai

    ai_result = {
        "attack_type": attack_type,
        "severity": "HIGH",
        "confidence": 90
    }

    generate_rule_from_ai(ai_result, src_ip)

    return {"status": attack_type}


@app.route("/api/dashboard-data")
def dashboard_data():
    total_attacks = sum(firewall.ATTACK_STATS.values()) if firewall.ATTACK_STATS else 0

    threat = "LOW"
    if total_attacks > 20:
        threat = "HIGH"
    if total_attacks > 50:
        threat = "CRITICAL"

    return jsonify({
        "packet_count": firewall.PACKET_COUNT,
        "blocked_count": len(firewall.BLOCKED_IPS),
        "attack_stats": {
            str(k): int(v)
            for k, v in firewall.ATTACK_STATS.items()
            if k and isinstance(v, (int, float))
        },
        "rules": [
            {
                **r,
                "source_zone": str(r.get("source_zone")),
                "dest_zone": str(r.get("dest_zone"))
            }
            for r in load_rules()
        ],
        "logs": get_recent_logs(),
        "blocked_ips": [
            {
                "ip": ip,
                "reason": data.get("reason"),
                "time": data.get("time")
            }
            for ip, data in firewall.BLOCKED_IPS.items()
        ],
        "timeline": {
            "labels": ["1h", "2h", "3h", "4h", "5h", "6h"],
            "values": [5, 12, 7, 20, 9, 15]
        },
        "threat_level": threat,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)