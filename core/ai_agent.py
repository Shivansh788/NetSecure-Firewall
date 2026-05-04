# core/ai_agent.py

import time
from core.rule_engine import add_ai_rule

# =========================================
# AGENT MEMORY
# =========================================

ATTACK_FREQUENCY = {}
GENERATED_RULES = {}

FREQUENCY_THRESHOLD = 3
CONFIDENCE_THRESHOLD = 80


def update_attack_frequency(ip):
    ATTACK_FREQUENCY[ip] = ATTACK_FREQUENCY.get(ip, 0) + 1


def get_attack_frequency(ip):
    return ATTACK_FREQUENCY.get(ip, 0)

# 🔥 Prevent duplicate rules

# =========================================
# MAIN AGENT FUNCTION
# =========================================

def generate_rule_from_ai(ai_result, src_ip):

    attack = ai_result.get("attack_type", "").upper()

    # 🔥 NORMALIZE ATTACK NAMES (CRITICAL FIX)
    if attack in ["SQL", "SQLI"]:
        attack = "SQL_INJECTION"

    elif attack in ["DOS", "FLOOD"]:
        attack = "DDOS"

    elif attack in ["TRAVERSAL", "PATH"]:
        attack = "PATH_TRAVERSAL"

    # ❌ Ignore garbage
    if not attack or attack in ["UNKNOWN", "BENIGN"]:
        return "[AI AGENT] Ignored non-malicious traffic"

    severity = ai_result.get("severity", "LOW")
    confidence = int(ai_result.get("confidence", 50))

    update_attack_frequency(src_ip)
    freq = get_attack_frequency(src_ip)

    rule_key = f"{src_ip}-{attack}"

    # ✅ 🔥 FIX: DUPLICATE CHECK (INSIDE FUNCTION)
    if rule_key in GENERATED_RULES:
        return "[AI AGENT] Duplicate rule skipped"

    # =========================================
    # 🎯 DECISION LOGIC
    # =========================================

    action = None
    ttl = 300
    reason = attack

    if freq >= FREQUENCY_THRESHOLD:
        action = "DROP"
        ttl = 600

    elif severity == "HIGH" and confidence >= CONFIDENCE_THRESHOLD:
        action = "DROP"
        ttl = 300

    elif severity in ["MEDIUM", "HIGH"]:
        action = "DROP"
        ttl = 120

    else:
        return "[AI AGENT] No rule created (low risk)"

    # =========================================
    # 🚀 APPLY RULE
    # =========================================

    try:
        rule = add_ai_rule(
            src_ip=src_ip,
            action=action,
            reason=reason,
            ttl=ttl
        )

        GENERATED_RULES[rule_key] = time.time()

        return (
            f"[AI AGENT] Rule applied | IP={src_ip} | "
            f"Action={action} | Attack={attack} | "
            f"Freq={freq} | TTL={ttl}s"
        )

    except Exception as e:
        return f"[AI AGENT ERROR] {e}"