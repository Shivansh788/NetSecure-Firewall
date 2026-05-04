# core/ai_analyzer.py

import json

# Mock LLM implementation
# To use with real Ollama: pip install ollama
# Then replace this with: from ollama import Client

class MockLLM:
    """Mock LLM that returns safe analysis results"""
    def __init__(self, api_key=None):
        self.api_key = api_key
    
    def generate(self, model, prompt, max_tokens=20000, temperature=0.2):
        """Mock response - returns safe default analysis"""
        # Simple heuristics for demo
        payload_lower = prompt.lower()
        
        # Check for common attack patterns
        attack_indicators = {
            'union': 'SQL_INJECTION',
            'drop': 'SQL_INJECTION',
            'exec': 'COMMAND_INJECTION',
            'bash': 'COMMAND_INJECTION',
            '${': 'TEMPLATE_INJECTION',
            'eval': 'CODE_INJECTION',
            '<script>': 'XSS',
            'javascript:': 'XSS',
            'onclick': 'XSS',
            '../': 'PATH_TRAVERSAL',
            '..\\': 'PATH_TRAVERSAL',
        }
        
        attack_type = "BENIGN"
        confidence = 5
        
        for indicator, attack in attack_indicators.items():
            if indicator in payload_lower:
                attack_type = attack
                confidence = 75
                break
        
        severity = "LOW" if confidence < 50 else "HIGH" if confidence > 70 else "MEDIUM"
        
        return json.dumps({
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "reason": f"Mock analysis detected {attack_type}",
            "recommended_action": "BLOCK" if confidence > 70 else "MONITOR"
        })

# Initialize once (IMPORTANT)
llm = MockLLM(api_key="YOUR_API_KEY")

def analyze_with_ai(payload: str):
    """
    Sends suspicious payload to AI for analysis
    Returns structured result (JSON string)
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
        return json.dumps({
            "attack_type": "ERROR",
            "severity": "LOW",
            "confidence": 0,
            "reason": str(e),
            "recommended_action": "MONITOR"
        })
