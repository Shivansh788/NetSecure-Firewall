import re

SIGNATURES = {
    "SQL_INJECTION": [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bOR\b\s+1=1)"
    ],
    "XSS_ATTACK": [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload="
    ],
    "COMMAND_INJECTION": [
        r";\s*ls",
        r";\s*cat",
        r";\s*whoami",
        r"\|\s*bash"
    ],
    "REVERSE_SHELL": [
        r"nc\s+-e",
        r"/bin/sh",
        r"/bin/bash"
    ]
}


def inspect_payload(payload):
    if not payload:
        return None

    payload = payload.lower()

    for attack_type, patterns in SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern.lower(), payload):
                return attack_type

    return None