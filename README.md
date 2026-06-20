# Realtime-IDPS: Network Intrusion Detection & Prevention System

A high-performance, decoupled Intrusion Detection and Prevention System (IDPS) that sniffs live network packets from a physical network interface, classifies security threats, streams metrics in real-time via WebSockets, and enforces automated firewall mitigation rules.

## 🚀 Key Features
- **Live Packet Sniffing:** Promiscuous mode packet capture using Scapy and Npcap/libpcap layers.
- **WebSocket Event Streaming:** Instantaneous UI synchronization using Supabase's realtime PostgreSQL replication protocol.
- **Automated Threat Mitigation:** Dynamic, automated OS-level firewall injection (`netsh advfirewall`) to block malicious source IPs the millisecond a critical anomaly is detected.
- **Modern Security Dashboard:** Real-time metrics visualization built with React, Vite, Tailwind CSS, and Lucide icons.

---

## 🛠️ Architecture Overview

```text
       +---------------------------------------------+
       |             Network Traffic (NIC)           |
       +----------------------+----------------------+
                              |
                              v  (Sniffs Promiscuous Mode via Npcap)
       +----------------------+----------------------+
       |       Python Backend / Scapy Agent          |
       |  - Classifies Traffic (Low, Medium, High)   |
       |  - Injects Windows Firewall Rules (IDPS)     |
       +----------------------+----------------------+
                              |
                              v  (SQL INSERT)
       +----------------------+----------------------+
       |            Supabase Database                |
       |  - Realtime Engine Enabled on 'packet_logs' |
       +----------------------+----------------------+
                              |
                              v  (Persistent WebSocket Feed)
       +----------------------+----------------------+
       |            React Frontend Dashboard         |
       |  - Live Security Ingestion Stream UI        |
       +----------------------+----------------------+



📋 Prerequisites
Before running the project, ensure you have the following installed on your machine:

Node.js (v18.0 or higher)

Python (v3.10 or higher)

Npcap (Required for Windows packet sniffing; ensure "Install Npcap in WinPcap API-compatible mode" is checked during installation).




⚙️ Project Structure

Realtime-IDPS/
├── backend/
│   ├── sniffer.py           # Core Scapy ingestion & firewall engine
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # React Dashboard Component
│   │   └── main.jsx
│   ├── package.json         # Node dependencies
│   └── vite.config.js
└── .gitignore               # Excludes node_modules and venv



🔧 Installation & Setup
1. Database Setup (Supabase)
Create a new project on Supabase.

2. Create a table named packet_logs with the following schema:

id (int8, Primary Key, Auto-incrementing)

created_at (timestamptz, default: now())

risk_level (text)

classification (text)

source_ip (text)

dest_ip (text)

protocol (text)

length (int4)

3 . Important: Enable Realtime replication for the packet_logs table under Database > Replication > Source.

4 . Retrieve your Project URL and Anon Public Key from Project Settings > API.


2. Backend Setup
1. Open an Administrator Command Prompt (Required to put your network card into promiscuous mode).

2. Navigate to the backend directory:

cd backend

Create and activate a virtual environment:

python -m venv venv
venv\Scripts\activate


Install the required modules:

pip install scapy supabase

Configure your Supabase credentials within sniffer.py and run the ingestion engine:

python sniffer.py

Frontend Setup
Open a second command prompt and navigate to the frontend directory:

cd frontend

Install the frontend dependencies:

npm install

Update the SUPABASE_URL and SUPABASE_KEY configuration variables directly inside src/App.jsx.

Spin up the local Vite development server:

npm run dev

Open your browser to http://localhost:5173 to view the live dashboard.


🛡️ Security & Mitigation Verification
When a threat level matches a malicious pattern profile, the background agent executes an automatic OS security rule:

Active Inspection Command: netsh advfirewall firewall show rule name=IDPS_BLOCK_IP

Clearing Rule Blocks: To manually lift a block injected during testing, run:

netsh advfirewall firewall delete rule name="IDPS_BLOCK_IP"
