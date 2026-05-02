# core/ai_parser.py

import json
import re

def parse_ai_response(response_text):
    """
    Extract JSON safely from AI output
    """
    try:
        # Extract JSON block
        match = re.search(r'\{.*\}', str(response_text), re.DOTALL)
        if match:
            data = json.loads(match.group())
            return data
    except:
        pass

    return {
        "attack_type": "UNKNOWN",
        "severity": "LOW",
        "confidence": 0,
        "reason": "Parsing failed",
        "recommended_action": "MONITOR"
    }
