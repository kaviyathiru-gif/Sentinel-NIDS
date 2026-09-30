# Sentinel MLDL Network Intrusion Detection System (NIDS)

Sentinel is an enterprise-grade, deep-learning-powered Network Intrusion Detection System (NIDS) designed for modern Security Operations Centers (SOC). It provides real-time packet flow inspection, distinguishes normal users from malicious attackers, identifies specific cyber attacks (such as port scanning and brute force), tracks attacker origins using global geo-tagging, integrates Power BI trend analytics, and executes automated threat mitigation sequences including Gmail alerts and emergency voice calls to system administrators.

---

## System Architecture

```
                                  [ Network Packet Stream / Ingestion ]
                                                    │
                                                    ▼
                               ┌──────────────────────────────────────────┐
                               │     Sentinel PyTorch Deep Learning       │
                               │           (SentinelNeuralIDS)            │
                               │  - 1D-CNN Feature Extractor              │
                               │  - Bidirectional LSTM Sequence Modeler   │
                               │  - Multi-Head Self-Attention Pooling     │
                               └────────────────────┬─────────────────────┘
                                                    │
                               ┌────────────────────┴─────────────────────┐
                               │                                          │
                               ▼                                          ▼
                      [ Binary Detector Head ]                [ Multi-Class Attack Head ]
                      - Authorized Normal User                - Normal Traffic
                      - Malicious Hacker / Intruder           - Port Scanning (SYN/FIN Sweep)
                                                              - Brute Force (SSH/Auth Storm)
                                                              - DDoS / SYN Flood
                                                              - Botnet C2 Beaconing
                                                    │
                                                    ▼
                               ┌──────────────────────────────────────────┐
                               │         Global Geo-Tagging Engine        │
                               │  (IP Lat/Lng, Country, City, ASN, ISP)   │
                               └────────────────────┬─────────────────────┘
                                                    │
                                                    ▼
                               ┌──────────────────────────────────────────┐
                               │        Firebase Firestore Database       │
                               │  Collections:                            │
                               │   - sentinel_incidents (Real-time events)│
                               │   - sentinel_traffic_logs (Raw telemetry)│
                               │   - sentinel_mitigations (Firewall rules)│
                               └────────────────────┬─────────────────────┘
                                                    │
             ┌──────────────────────────────────────┼──────────────────────────────────────┐
             │                                      │                                      │
             ▼                                      ▼                                      ▼
┌───────────────────────────┐          ┌───────────────────────────┐          ┌───────────────────────────┐
│     HTML5 SOC Dashboard   │          │ Power BI Analytics Hub    │          │ Threat Mitigation Engine  │
│ - Leaflet.js Global Map   │          │ - 24-Hour Trend Analysis  │          │ - Gmail Alert to Admin    │
│ - Live Traffic Ingestion  │          │ - Port Vulnerability Map  │          │ - Automated Voice Calling │
│ - Attack Injection Studio │          │ - MTTD / MTTM Breakdown   │          │ - Auto-Firewall Drop Rule │
└───────────────────────────┘          └───────────────────────────┘          └───────────────────────────┘
```

---

## Key Features

1. **PyTorch Hybrid Neural Architecture (`SentinelNeuralIDS`)**:
   - Evaluates 24 statistical flow features including port entropy, packet length variance, SYN/ACK ratios, and inter-arrival times.
   - Dual-head output: provides independent probability for malicious attacker detection alongside granular multi-class categorization.
2. **Accurate Attack Differentiation**:
   - **Normal Users**: Typical browsing/streaming profiles with standard port entropy and low connection retry rate.
   - **Port Scanning**: Identified via elevated destination port entropy, high SYN flags with zero payload, and rapid port sweeping.
   - **Brute Force**: Identified through repeated authentication failures, high PSH flags, and sustained credential retry frequency.
3. **Global Geo-Tagging**:
   - Maps originating attacker IP addresses to exact geographic coordinates, country, city, and ISP/Autonomous System.
   - Plotted in real-time onto an interactive Leaflet.js world map with animated pulsating threat pins.
4. **Power BI Visual Analytics**:
   - Embedded interactive dashboard mirroring Microsoft Power BI telemetry.
   - 24-Hour attack volume comparisons, geographic origin distributions, targeted port breakdown, and Mean Time to Detect (MTTD) tracking.
5. **Automated Mitigation & Emergency Notification Sequence**:
   - High-impact cyber alert emails formatted with full forensic evidence dispatched to the admin's Gmail.
   - Automated emergency calling sequence (Twilio Voice API / Webhook) triggered for High and Critical incidents.
   - Automated generation and enforcement of defensive firewall perimeter rules (`iptables`, AWS NACL, and Cloudflare WAF).

---

## Directory Structure

```
sentinel_nids/
├── model/
│   ├── model.py            # PyTorch SentinelNeuralIDS dual-head architecture
│   ├── dataset.py          # Benchmark flow generator & preprocessor
│   ├── train.py            # Training loop, evaluation, and checkpoint saving
│   ├── inference.py        # Real-time inference engine with feature extraction
│   └── checkpoints/        # Exported model weights and preprocessor parameters
├── backend/
│   ├── app.py              # REST API & static server
│   ├── firestore_service.py # Firebase Firestore integration and real-time syncing
│   ├── geotagging.py       # Global IP geolocation and threat enrichment
│   └── alert_service.py    # Admin Gmail dispatcher, voice calling, & firewall mitigation
├── frontend/
│   ├── index.html          # HTML5 Sentinel SOC Dashboard
│   ├── styles.css          # Dark neon cyber Operations Center UI
│   └── app.js              # Leaflet map, Chart.js Power BI canvas, & stream controls
├── config/
│   ├── firebase_config.js  # Firebase Web SDK initialization & subscriptions
│   ├── firestore.rules     # Cloud Firestore security rules
│   └── powerbi_embed_spec.json # Power BI embed specifications & DAX formulas
└── requirements.txt        # Python dependencies
```

---

## Setup & Running the Application

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
Create a `.env` file or export the following variables:
```bash
export SENTINEL_ADMIN_EMAIL="admin.security@sentinel-soc.internal"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-soc-alert@gmail.com"
export SMTP_PASSWORD="your-app-password"
export SENTINEL_ADMIN_PHONE="+15550199832"
export TWILIO_ACCOUNT_SID="your_twilio_sid"
export TWILIO_AUTH_TOKEN="your_twilio_auth_token"
export TWILIO_FROM_PHONE="+15551234567"
```

### 3. Launch the Server
```bash
python3 backend/app.py 8080
```
Open your browser and navigate to `http://localhost:8080` to access the Sentinel Security Operations Center.
