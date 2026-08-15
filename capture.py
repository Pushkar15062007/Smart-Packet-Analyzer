"""
===========================================================
SMART PACKET ANALYZER v5.0
CAPTURE ENGINE
===========================================================
"""

from scapy.all import *
from collections import Counter
from datetime import datetime

import json
import os
import psutil
import threading
import time

# ===========================================================
# CONFIGURATION
# ===========================================================

DATA_FILE = "data/packets.json"

MAX_PACKETS = 100

packets = []

protocol_counter = Counter()

total_packets = 0

alerts = 0

lock = threading.Lock()

# ===========================================================
# BANDWIDTH
# ===========================================================

previous = psutil.net_io_counters()

bandwidth = {

    "download": 0,

    "upload": 0,

    "total": 0

}


def update_bandwidth():

    global previous

    while True:

        current = psutil.net_io_counters()

        download = (current.bytes_recv - previous.bytes_recv) / 1024 / 1024

        upload = (current.bytes_sent - previous.bytes_sent) / 1024 / 1024

        bandwidth["download"] = round(download, 2)

        bandwidth["upload"] = round(upload, 2)

        bandwidth["total"] = round(download + upload, 2)

        previous = current

        time.sleep(1)

# ===========================================================
# PROTOCOL DETECTION
# ===========================================================


def detect_protocol(packet):

    if packet.haslayer(TCP):

        sport = packet[TCP].sport

        dport = packet[TCP].dport

        if 80 in (sport, dport):

            return "HTTP"

        if 443 in (sport, dport):

            return "HTTPS"

        return "TCP"

    if packet.haslayer(UDP):

        sport = packet[UDP].sport

        dport = packet[UDP].dport

        if 53 in (sport, dport):

            return "DNS"

        return "UDP"

    if packet.haslayer(ICMP):

        return "ICMP"

    return "OTHER"

# ===========================================================
# AI RISK DETECTION
# ===========================================================


def detect_risk(packet):

    if packet.haslayer(TCP):

        flags = str(packet[TCP].flags)

        if "S" in flags and "A" not in flags:

            return "MEDIUM"

    if packet.haslayer(ICMP):

        return "LOW"

    return "LOW"

# ===========================================================
# HEX DUMP
# ===========================================================


def packet_hex(packet):

    try:

        return bytes(packet).hex(" ")

    except Exception:

        return ""
# ===========================================================
# PACKET PARSER
# ===========================================================

def parse_packet(packet):

    protocol = detect_protocol(packet)

    risk = detect_risk(packet)

    packet_data = {

        "time": datetime.now().strftime("%H:%M:%S"),

        "src": "-",

        "dst": "-",

        "protocol": protocol,

        "length": len(packet),

        "risk": risk,

        "port": "-",

        "src_port": "-",

        "src_mac": "-",

        "dst_mac": "-",

        "eth_type": "-",

        "ttl": "-",

        "flags": "-",

        "window": "-",

        "hex": packet_hex(packet),

        # HTTP

        "http_method": "-",

        "http_host": "-",

        "http_uri": "-",

        "user_agent": "-",

        # DNS

        "dns_query": "-",

        "dns_response": "-",

        "dns_type": "-",

        # TLS

        "tls_version": "-",

        "sni": "-",

        "cipher": "-"

    }

    # =======================================================
    # Ethernet Layer
    # =======================================================

    if packet.haslayer(Ether):

        eth = packet[Ether]

        packet_data["src_mac"] = eth.src

        packet_data["dst_mac"] = eth.dst

        packet_data["eth_type"] = hex(eth.type)

    # =======================================================
    # IP Layer
    # =======================================================

    if packet.haslayer(IP):

        ip = packet[IP]

        packet_data["src"] = ip.src

        packet_data["dst"] = ip.dst

        packet_data["ttl"] = ip.ttl

    # =======================================================
    # TCP
    # =======================================================

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        packet_data["src_port"] = tcp.sport

        packet_data["port"] = tcp.dport

        packet_data["flags"] = str(tcp.flags)

        packet_data["window"] = tcp.window

    # =======================================================
    # UDP
    # =======================================================

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        packet_data["src_port"] = udp.sport

        packet_data["port"] = udp.dport

    # =======================================================
    # DNS
    # =======================================================

    if packet.haslayer(DNS):

        dns = packet[DNS]

        try:

            if dns.qd:

                packet_data["dns_query"] = dns.qd.qname.decode(
                    errors="ignore"
                )

                packet_data["dns_type"] = dns.qd.qtype

        except Exception:

            pass

        try:

            if dns.an:

                packet_data["dns_response"] = str(dns.an.rdata)

        except Exception:

            pass

    # =======================================================
    # HTTP (Raw Payload)
    # =======================================================

    if packet.haslayer(Raw):

        try:

            payload = packet[Raw].load.decode(
                errors="ignore"
            )

            lines = payload.split("\r\n")

            if len(lines):

                first = lines[0]

                methods = [

                    "GET",

                    "POST",

                    "PUT",

                    "DELETE",

                    "HEAD",

                    "OPTIONS",

                    "PATCH"

                ]

                for method in methods:

                    if first.startswith(method):

                        packet_data["http_method"] = method

                        parts = first.split()

                        if len(parts) > 1:

                            packet_data["http_uri"] = parts[1]

                        break

            for line in lines:

                lower = line.lower()

                if lower.startswith("host:"):

                    packet_data["http_host"] = line.split(
                        ":",1
                    )[1].strip()

                elif lower.startswith("user-agent:"):

                    packet_data["user_agent"] = line.split(
                        ":",1
                    )[1].strip()

        except Exception:

            pass

    # =======================================================
    # TLS Placeholder
    # =======================================================

    if protocol == "HTTPS":

        packet_data["tls_version"] = "TLS"

        packet_data["sni"] = "Encrypted"

        packet_data["cipher"] = "Encrypted"

    return packet_data
# ===========================================================
# PACKET HANDLER
# ===========================================================

def process_packet(packet):

    global total_packets
    global alerts

    try:

        packet_data = parse_packet(packet)

        with lock:

            packets.append(packet_data)

            if len(packets) > MAX_PACKETS:
                packets.pop(0)

            total_packets += 1

            protocol_counter[packet_data["protocol"]] += 1

            if packet_data["risk"] in ["HIGH", "CRITICAL"]:
                alerts += 1

            save_data()

    except Exception as e:

        print("Packet Processing Error:", e)

# ===========================================================
# SAVE DASHBOARD DATA
# ===========================================================

def save_data():

    protocol_counts = {

        "TCP": protocol_counter.get("TCP", 0),
        "UDP": protocol_counter.get("UDP", 0),
        "HTTP": protocol_counter.get("HTTP", 0),
        "HTTPS": protocol_counter.get("HTTPS", 0),
        "DNS": protocol_counter.get("DNS", 0),
        "ICMP": protocol_counter.get("ICMP", 0),
        "OTHER": protocol_counter.get("OTHER", 0)

    }

    active_hosts = len({

        p["src"]

        for p in packets

        if p["src"] != "-"

    })

    avg_packet = 0

    if packets:

        avg_packet = round(

            sum(p["length"] for p in packets) / len(packets),

            2

        )

    top_host = "-"

    if packets:

        host_counter = Counter(

            p["src"]

            for p in packets

            if p["src"] != "-"

        )

        if host_counter:

            top_host = host_counter.most_common(1)[0][0]

    security_score = max(

        0,

        100 - alerts

    )

    network_health = "Healthy"

    if alerts > 20:

        network_health = "Critical"

    elif alerts > 10:

        network_health = "Warning"

    dashboard = {

        "dashboard": {

            "packets": total_packets,

            "protocols": len(

                [

                    k for k, v in protocol_counter.items()

                    if v > 0

                ]

            ),

            "alerts": alerts,

            "status": "Monitoring"

        },

        "security": {

            "score": security_score,

            "health": network_health,

            "active_hosts": active_hosts,

            "avg_packet": avg_packet,

            "top_host": top_host

        },

        "bandwidth": bandwidth,

        "protocols": protocol_counts,

        "packets": packets,

        "insights": [

            {

                "title": "Traffic",

                "message":

                f"Captured {total_packets} packets."

            },

            {

                "title": "Threats",

                "message":

                f"{alerts} suspicious packets detected."

            },

            {

                "title": "Top Protocol",

                "message":

                max(

                    protocol_counts,

                    key=protocol_counts.get

                )

            }

        ]

    }

    os.makedirs(

        os.path.dirname(DATA_FILE),

        exist_ok=True

    )

    with open(

        DATA_FILE,

        "w"

    ) as f:

        json.dump(

            dashboard,

            f,

            indent=4

        )

# ===========================================================
# START SNIFFING
# ===========================================================

def sniff_packets():

    sniff(

        prn=process_packet,

        store=False

    )

# ===========================================================
# START CAPTURE ENGINE
# ===========================================================

def start_capture():

    threading.Thread(

        target=update_bandwidth,

        daemon=True

    ).start()

    threading.Thread(

        target=sniff_packets,

        daemon=True

    ).start()

    print("===================================")
    print(" Smart Packet Analyzer Started")
    print(" Capturing Network Traffic...")
    print("===================================")

# ===========================================================
# MAIN
# ===========================================================

if __name__ == "__main__":

    start_capture()

    while True:

        time.sleep(1)