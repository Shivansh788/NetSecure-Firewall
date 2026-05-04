# 🔥 NetSecure Firewall

### AI-Powered Intelligent Firewall with IDS, IPS, Zero-Day Detection & Agentic Defense

---

## ⚙️ Installation & Setup

### 1️⃣ Create Virtual Environment
python -m venv myenv

### 2️⃣ Activate Environment
.\myenv\Scripts\Activate.ps1   # Windows  
source myenv/bin/activate      # Linux/Mac  

### 3️⃣ Install Dependencies
pip install -r requirements.txt

### 4️⃣ Run the Firewall
python run.py

---

## 📌 Overview

NetSecure Firewall is an advanced Next-Generation Firewall (NGFW) that integrates:

- Firewall (Zone-Based + Zero Trust)
- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- AI Threat Analysis
- Agentic Rule Generation
- Behavioral & Anomaly Detection
- Real-time Dashboard

Unlike traditional firewalls, NetSecure is:
- Adaptive
- Explainable
- AI-driven
- Interactive (Simulation-enabled)

---

## 🚀 Core Features

---

### 🔐 1. Zero Trust Zone-Based Firewall

- Default policy: DROP (deny all)
- Zones:
  - PUBLIC
  - INTERNAL
  - RESTRICTED
- Traffic filtering based on:
  - Source Zone
  - Destination Zone
  - Protocol & Port
- Real-time enforcement

---

### 🔍 2. Intrusion Detection System (IDS)

Detects known attacks:

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Large Payload Attacks

---

### 🧠 3. Deep Packet Inspection (DPI)

- Payload inspection
- Detects hidden threats
- Application-layer attack detection

---

### ⚡ 4. Intrusion Prevention System (IPS)

- Threat scoring per IP
- Automatic blocking
- Temporary block with expiry
- Rate limiting & flood detection

---

### 🧬 5. Behavioral & Zero-Day Detection

Detects unknown attacks using anomaly patterns:

- Traffic spikes
- Abnormal payload size
- Unknown patterns

If no signature is matched:

→ Marked as ZERO_DAY  
→ AI generates rule  
→ Traffic blocked  

---

### 🤖 6. AI-Powered Threat Analysis

AI outputs:

- Attack Type
- Severity
- Confidence
- Reasoning

---

### 🤖 7. Agentic AI Rule Generation

- Automatic rule creation
- Based on:
  - Severity
  - Confidence
  - Frequency
- Duplicate prevention
- TTL-based expiry

---

### 🔄 8. Dynamic Rule Management

- AI + Manual rules
- Enable/Disable rules from UI
- Conflict detection
- Deduplication

---

### 🎮 9. Attack Simulation Engine

Simulate:

- SQL Injection
- XSS
- Path Traversal
- DDoS
- Zero-Day Attacks

Each simulation:
- Updates dashboard
- Generates logs
- Triggers AI
- Creates rules

---

### 📊 10. Real-Time Dashboard

Includes:

- Attack distribution chart
- Threat map
- AI Sentinel panel
- Live logs
- Popup alerts
- Firewall policies table
- Active threats list

---

### 🎛️ 11. UI-Controlled Firewall

- Toggle rules ON/OFF
- Backend synced
- Real-time updates

---

### 🧠 12. Hybrid Rule System

| Type   | Description |
|--------|------------|
| MANUAL | Zone-based rules |
| AI     | Attack-based rules |

---

## 🏗️ System Architecture

Incoming Traffic  
↓  
Firewall Rules  
↓  
IDS Detection  
↓  
DPI Inspection  
↓  
Behavior Analysis  
↓  
AI Analyzer  
↓  
AI Agent (Rule Generation)  
↓  
IPS Decision Engine  
↓  
Allow / Block  

---

## 📂 Project Structure

NetSecure_Firewall/

core/
- firewall.py
- rule_engine.py
- ai_agent.py
- ai_analyzer.py
- ai_parser.py
- ids.py
- dpi.py
- behavior_monitor.py
- conflict_detector.py

ui/
- app.py

config/
- rules.json

logs/
- events.log

run.py  
requirements.txt  
README.md  

---

## 🧪 Simulation Workflow

Click Attack Button  
↓  
Simulation API  
↓  
Logs & Stats Updated  
↓  
AI Triggered  
↓  
Rule Generated  
↓  
UI Updated  

---

## 📊 Logging

Logs stored in:
logs/events.log

Includes:
- IDS alerts
- DPI detections
- AI decisions
- Rule creation
- Threat levels

---

## 🎯 Objectives Achieved

- Zone-based firewall (Zero Trust)
- IDS + IPS integration
- Deep Packet Inspection
- Behavioral analysis
- Zero-Day detection
- AI-based rule generation
- Conflict detection
- Real-time dashboard

---

## 🚀 Advanced Features

- Agentic AI firewall
- Simulation-based demo
- Hybrid rule architecture
- Explainable AI
- UI-controlled rules

---

## 📈 Future Scope

- ML-based anomaly detection
- Real Geo-IP blocking
- Distributed firewall
- SIEM integration
- Cloud deployment

---

## 🏁 Conclusion

NetSecure Firewall demonstrates a modern cybersecurity system that:

- Detects known and unknown attacks
- Adapts dynamically using AI
- Provides real-time monitoring
- Enforces Zero Trust security

It integrates:

Firewall + IDS + IPS + AI + Behavior + UI

into a complete Next-Generation Firewall system.

---

## ⭐ Star the repository if you found it useful!
