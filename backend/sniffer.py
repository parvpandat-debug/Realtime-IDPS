import os
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from supabase import create_client, Client

# Hardcoded credentials to bypass .env read errors
SUPABASE_URL = "https://qvjbxeoupprtjfnosisl.supabase.co"
SUPABASE_KEY = "sb_publishable_IdzeKwHTr8sFGIe2x3uXzQ_cQMEefJv"

# Initialize our connection client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Tracking data structures for intrusion rules
ip_traffic_counts = defaultdict(int)
WINDOW_SIZE = 5.0  # Reset monitoring analytics every 5 seconds
last_reset = time.time()

def clear_traffic_metrics():
    """Background worker loop to flush rate-tracking metrics periodically"""
    global last_reset
    while True:
        time.sleep(WINDOW_SIZE)
        ip_traffic_counts.clear()
        last_reset = time.time()

# Spin up the tracker flush in an independent background thread
threading.Thread(target=clear_traffic_metrics, daemon=True).start()

def process_network_packet(packet):
    """Callback function executed automatically for every caught packet"""
    if not packet.haslayer(IP):
        return

    # Extract foundational headers
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)
    
    # Keep tally of request rates per source IP
    ip_traffic_counts[src_ip] += 1
    
    # Identify protocol
    protocol = "Other"
    if packet.haslayer(TCP): protocol = "TCP"
    elif packet.haslayer(UDP): protocol = "UDP"

    # Default baseline triage status
    risk_level = "Low"
    attack_type = "Normal"

    # --- INTRUSION DETECTION RULES ---
    # Rule A: Flooding detection (Simulating a DDoS attempt)
    if ip_traffic_counts[src_ip] > 50:
        risk_level = "High"
        attack_type = "DDoS Attempt"
    
    # Rule B: Scan vectors targeting common administrative management lines
    elif packet.haslayer(TCP) and packet[TCP].dport in [22, 23, 445, 3389]:
        risk_level = "Medium"
        attack_type = "Port Scan Vector"
        
    # Rule C: Suspiciously large payload anomalies
    elif packet_size > 1450:
        risk_level = "Medium"
        attack_type = "Oversized Fragment"

    # Compile dataset package
    packet_payload = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "packet_size": packet_size,
        "risk_level": risk_level,
        "attack_type": attack_type
    }

    # Dispatch record asynchronously to our Supabase table
    try:
        response = supabase.table("packet_logs").insert(packet_payload).execute()
        print(f"📡 Ingested: {src_ip} -> {dst_ip} | Class: {attack_type} ({risk_level})")
    except Exception as error:
        print(f"❌ Failed streaming pipeline log: {error}")

if __name__ == "__main__":
    print("======================================================")
    print("🚀 IDPS Backend Node Operational. intercepting raw packets...")
    print("======================================================")
    
    try:
        # Begin capture loop. store=0 drops processed memory immediately to save RAM
        sniff(prn=process_network_packet, store=0)
    except PermissionError:
        print("\n🔒 Permission Error: Network interfaces require Administrative privileges.")
        print("Please restart this Command Prompt by choosing 'Run as Administrator'.")