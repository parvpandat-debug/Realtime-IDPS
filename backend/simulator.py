import time
from scapy.all import send, IP, TCP

print("⚔️ Starting localized DDoS flood simulation...")
print("Sending 60 dummy packets from 192.168.1.99 to test IDPS firewall blocking...")

# Target a dummy internal IP layout 
for i in range(61):
    # Construct a raw fake IP layer targeting your system loop
    packet = IP(src="192.168.1.99", dst="192.168.1.5") / TCP(dport=80, flags="S")
    send(packet, verbose=False)
    time.sleep(0.02)  # Fire them in rapid succession

print("✅ Simulation stream complete! Check your sniffer terminal.")