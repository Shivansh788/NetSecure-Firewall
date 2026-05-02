# core/ai_analyzer.py

from coeai import LLMinfer

# Initialize once (IMPORTANT)
llm = LLMinfer(api_key="YOUR_API_KEY")  # replace

def analyze_with_ai(payload: str):
    """
    Sends suspicious payload to COE AI for analysis
    Returns structured result
    """
    try:
        prompt = f"""
You are a cybersecurity expert.

Analyze the following HTTP request and determine if it is malicious.

Request:
{payload}

Return ONLY in JSON format:
{{
    "attack_type": "...",
    "severity": "LOW/MEDIUM/HIGH",
    "confidence": "0-100",
    "reason": "...",
    "recommended_action": "ALLOW/BLOCK/MONITOR"
}}
"""

        response = llm.generate(
            model="tinyllama:latest",
            prompt=prompt,
            max_tokens=20000,
            temperature=0.2
        )

        return response  # raw response (we'll parse later)

    except Exception as e:
        return {
            "attack_type": "ERROR",
            "severity": "LOW",
            "confidence": 0,
            "reason": str(e),
            "recommended_action": "MONITOR"
        }
