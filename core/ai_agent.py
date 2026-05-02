# core/ai_agent.py

import time
from core.rule_engine import add_ai_rule

# =========================================
# AGENT MEMORY
# =========================================

ATTACK_FREQUENCY = {}
GENERATED_RULES = set()

FREQUENCY_THRESHOLD = 3
CONFIDENCE_THRESHOLD = 80


def update_attack_frequency(ip):
    ATTACK_FREQUENCY[ip] = ATTACK_FREQUENCY.get(ip, 0) + 1


def get_attack_frequency(ip):
    return ATTACK_FREQUENCY.get(ip, 0)


# =========================================
# MAIN AGENT FUNCTION
# =========================================

def generate_rule_from_ai(ai_result, src_ip):
    """
    Agentic Logic:
    - Uses AI output
    - Considers history
    - Creates adaptive rules
    - Avoids duplicates
    """

    attack = ai_result.get("attack_type", "UNKNOWN")
    severity = ai_result.get("severity", "LOW")
    confidence = int(ai_result.get("confidence", 50))

    update_attack_frequency(src_ip)
    freq = get_attack_frequency(src_ip)

    rule_key = f"{src_ip}-{attack}"

    if rule_key in GENERATED_RULES:
        return f"[AI AGENT] Rule already exists for {src_ip} ({attack})"

    # =========================================
    # 🎯 DECISION LOGIC
    # =========================================

    action = None
    ttl = 300
    reason = attack

    # 🔥 repeated attacker → strict
    if freq >= FREQUENCY_THRESHOLD:
        action = "DROP"
        reason = f"REPEATED_{attack}"
        ttl = 600

    # 🔥 high severity + high confidence
    elif severity == "HIGH" and confidence >= CONFIDENCE_THRESHOLD:
        action = "DROP"
        ttl = 300

    # 🔥 medium severity → temporary monitor
    elif severity == "MEDIUM":
        action = "DROP"
        ttl = 120

    else:
        return "[AI AGENT] No rule created (low risk)"

    # =========================================
    # 🚀 APPLY RULE (via rule engine)
    # =========================================

    try:
        rule = add_ai_rule(
            src_ip=src_ip,
            action=action,
            reason=reason,
            ttl=ttl
        )

        GENERATED_RULES.add(rule_key)

        return (
            f"[AI AGENT] Rule applied | IP={src_ip} | "
            f"Action={action} | Attack={attack} | "
            f"Freq={freq} | TTL={ttl}s"
        )

    except Exception as e:
        return f"[AI AGENT ERROR] {e}"
