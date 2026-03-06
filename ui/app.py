from flask import Flask, render_template_string
import os
from datetime import datetime
from core.ids import blocked_ips

app = Flask(__name__)

def get_logs():
    if os.path.exists("logs/events.log"):
        with open("logs/events.log", "r") as f:
            lines = f.readlines()
        return lines
    return []

@app.route("/")
def dashboard():
    logs = get_logs()
    total_requests = len(logs)
    blocked_count = len(blocked_ips)

    # Extract alerts for table
    alerts = []
    for line in logs[-10:]:
        threat_type = "Normal"
        severity = "LOW"
        action = "Allowed"

        if "PORT_SCAN" in line:
            threat_type = "Port Scan"
            severity = "HIGH"
            action = "Blocked"
        elif "BRUTE_FORCE" in line:
            threat_type = "Brute Force"
            severity = "CRITICAL"
            action = "Blocked"
        elif "ANOMALOUS" in line:
            threat_type = "Anomaly"
            severity = "MEDIUM"
            action = "Logged"
        elif "DROP" in line:
            threat_type = "Firewall Rule"
            severity = "HIGH"
            action = "Blocked"

        alerts.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "ip": line.split()[3] if len(line.split()) > 3 else "Unknown",
            "type": threat_type,
            "severity": severity,
            "action": action
        })

    return render_template_string(TEMPLATE,
        total_requests=total_requests,
        blocked_count=blocked_count,
        alerts=alerts,
        current_time=datetime.utcnow().strftime("%H:%M:%S")
    )

TEMPLATE = """ 
<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NetSecure Firewall Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600;700&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" rel="stylesheet"/>
<style>
body { font-family: 'Space Grotesk', sans-serif; }
.glass {
    background: rgba(22,27,34,0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255,255,255,0.1);
}
</style>
</head>
<body class="bg-black text-white min-h-screen flex flex-col">

<header class="h-16 border-b border-gray-800 flex items-center justify-between px-6 bg-black sticky top-0">
<div class="flex items-center gap-3">
<div class="size-8 bg-blue-500 rounded-lg flex items-center justify-center">
<span class="material-symbols-outlined">shield</span>
</div>
<h1 class="text-xl font-bold">NetSecure <span class="text-blue-400 font-light">Firewall + IDS</span></h1>
</div>

<div class="flex items-center gap-6">
<div class="text-green-400 text-xs font-bold tracking-wider">SYSTEM ACTIVE</div>
<div class="font-mono text-gray-400">{{ current_time }} UTC</div>
</div>
</header>

<div class="flex flex-1">
<!-- Sidebar -->
<aside class="w-60 border-r border-gray-800 bg-black p-6">
<p class="text-xs text-gray-500 uppercase mb-4">Monitoring</p>
<a class="block py-2 text-blue-400">Overview</a>
<a class="block py-2 text-gray-400 hover:text-blue-400">Live Traffic</a>
<a class="block py-2 text-gray-400 hover:text-blue-400">Threat Detection</a>
</aside>

<main class="flex-1 p-6 space-y-6">

<!-- Metrics -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
<div class="glass p-5 rounded-xl">
<span class="text-gray-400 text-xs uppercase">Total Requests</span>
<h3 class="text-2xl font-bold mt-2">{{ total_requests }}</h3>
</div>

<div class="glass p-5 rounded-xl">
<span class="text-gray-400 text-xs uppercase">Blocked Requests</span>
<h3 class="text-2xl font-bold mt-2 text-red-500">{{ blocked_count }}</h3>
</div>

<div class="glass p-5 rounded-xl">
<span class="text-gray-400 text-xs uppercase">Risk Level</span>
<h3 class="text-2xl font-bold mt-2 text-blue-400">LOW</h3>
</div>
</div>

<!-- Alerts Table -->
<div class="glass rounded-xl overflow-hidden">
<div class="p-6 border-b border-gray-800">
<h2 class="text-lg font-bold">Intrusion Detection Alerts</h2>
</div>

<table class="w-full text-left">
<thead class="bg-gray-900 text-gray-400 text-xs uppercase">
<tr>
<th class="px-6 py-3">Time</th>
<th class="px-6 py-3">Source IP</th>
<th class="px-6 py-3">Threat Type</th>
<th class="px-6 py-3">Severity</th>
<th class="px-6 py-3">Action</th>
</tr>
</thead>
<tbody>
{% for alert in alerts %}
<tr class="border-b border-gray-800 hover:bg-gray-900">
<td class="px-6 py-4 font-mono text-xs">{{ alert.time }}</td>
<td class="px-6 py-4 font-mono">{{ alert.ip }}</td>
<td class="px-6 py-4">{{ alert.type }}</td>
<td class="px-6 py-4">
<span class="px-2 py-1 text-xs rounded
{% if alert.severity == 'CRITICAL' %} bg-red-600 {% elif alert.severity == 'HIGH' %} bg-red-500 {% elif alert.severity == 'MEDIUM' %} bg-yellow-500 {% else %} bg-blue-500 {% endif %}">
{{ alert.severity }}
</span>
</td>
<td class="px-6 py-4">{{ alert.action }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

</main>
</div>

<footer class="border-t border-gray-800 text-center text-xs text-gray-500 py-4">
NetSecure Firewall © 2026 | Intelligent Web Application Firewall | UPES
</footer>

</body>
</html>
"""

if __name__ == "__main__":
    app.run(port=5000)