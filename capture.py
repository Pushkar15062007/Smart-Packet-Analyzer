from scapy.all import sniff, IP
from datetime import datetime
from collections import Counter
import statistics
import json
import os

from network.protocols import protocol_name
from ai.detector import detect_threat
from ai.risk import calculate_risk

DATA_FILE = "data/packets.json"

os.makedirs("data", exist_ok=True)

# ===========================
# Global Data
# ===========================

packets = []
packet_count = 0
protocols = set()

current_alerts = []
current_risk = "LOW"

protocol_counter = {
    "TCP": 0,
    "UDP": 0,
    "HTTP": 0,
    "HTTPS": 0,
    "DNS": 0,
    "ICMP": 0,
    "OTHER": 0
}

host_counter = Counter()

packet_sizes = []

total_bytes = 0

security_score = 100


# ===========================
# Save Dashboard Data
# ===========================

def save_data():

    global security_score

    # -----------------------
    # Average Packet Size
    # -----------------------

    avg_packet = 0

    if packet_sizes:
        avg_packet = int(statistics.mean(packet_sizes))

    # -----------------------
    # Network Health
    # -----------------------

    if security_score >= 90:
        network_health = "Excellent"

    elif security_score >= 75:
        network_health = "Good"

    elif security_score >= 50:
        network_health = "Warning"

    else:
        network_health = "Critical"

    # -----------------------
    # Dashboard Cards
    # -----------------------

    dashboard = {

        "packets": packet_count,

        "protocols": len(protocols),

        "alerts": len(current_alerts),

        "status": current_risk

    }

    # -----------------------
    # Security Dashboard
    # -----------------------

    security = {

        "score": security_score,

        "health": network_health,

        "active_hosts": len(host_counter),

        "avg_packet": avg_packet,

        "top_host": host_counter.most_common(1)[0][0] if host_counter else "-"

    }

    # -----------------------
    # AI Insights
    # -----------------------

    if current_alerts:

        insights = [f" {x}" for x in current_alerts]

    else:

        insights = [

            "✅ Network Operating Normally",

            f"Total Packets : {packet_count}",

            f"Protocols : {', '.join(sorted(protocols))}",

            f"Average Packet : {avg_packet} Bytes"

        ]

    # -----------------------
    # Final JSON
    # -----------------------

    data = {

        "dashboard": dashboard,

        "security": security,

        "protocols": protocol_counter,

        "packets": packets[-50:],

        "insights": insights

    }

    with open(DATA_FILE, "w") as f:

        json.dump(data, f, indent=4)


# ===========================
# Packet Processing
# ===========================

def process_packet(packet):

    global packet_count
    global current_alerts
    global current_risk
    global total_bytes
    global security_score

    if not packet.haslayer(IP):
        return

    proto = protocol_name(packet)

    packet_count += 1

    protocols.add(proto)

    protocol_counter[proto] += 1

    total_bytes += len(packet)

    packet_sizes.append(len(packet))

    packet_data = {

        "time": datetime.now().strftime("%H:%M:%S"),

        "src": packet[IP].src,

        "dst": packet[IP].dst,

        "protocol": proto,

        "length": len(packet)

    }

    packets.append(packet_data)

    host_counter[packet_data["src"]] += 1
    host_counter[packet_data["dst"]] += 1

    # -----------------------
    # AI Detection
    # -----------------------

    current_alerts = detect_threat(packet_data)

    current_risk = calculate_risk(current_alerts)

    # -----------------------
    # Security Score
    # -----------------------

    security_score = 100

    penalties = {

        "Large Packet": 5,

        "Unknown": 10,

        "DNS Flood": 20,

        "HTTPS": 15,

        "High Traffic": 20

    }

    for alert in current_alerts:

        for keyword, penalty in penalties.items():

            if keyword in alert:

                security_score -= penalty

    security_score = max(0, security_score)

    save_data()

    print(
        f"[{packet_count:5}] "
        f"{packet_data['src']} -> "
        f"{packet_data['dst']} | "
        f"{packet_data['protocol']} | "
        f"{packet_data['length']} Bytes | "
        f"Risk: {current_risk} | "
        f"Security: {security_score}%"
    )


# ===========================
# Start Sniffer
# ===========================

print("=" * 70)
print(" Smart Packet Analyzer Version 3.2")
print("Real-Time Network Security Monitoring Started")
print("=" * 70)

sniff(
    prn=process_packet,
    store=False
)