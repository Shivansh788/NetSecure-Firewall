import re

SIGNATURES = {
    "SQL_INJECTION": [r"UNION.*SELECT", r"OR 1=1", r"DROP TABLE", r"SELECT .* FROM"],
    "XSS_ATTACK": [r"<script>", r"javascript:", r"onerror=", r"onload="],
    "COMMAND_INJECTION": [
        r"; ls",
        r"; cat",
        r"\|\s*bash",
        r"&&",
    ],
    "LFI_RFI": [
        r"\.\./",
        r"/etc/passwd",
        r"php://input",
    ],
    "DNS_TUNNELING": [
        r"[A-Za-z0-9]{30,}\.com",
    ],
    "RCE_ATTEMPT": [r"system\(", r"exec\(", r"shell_exec\("],
}


def inspect(payload):

    if not payload:
        return None

    for attack_type, patterns in SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return attack_type

    return None
