from collections import Counter

packet_history = []


def detect_threat(packet):

    alerts = []

    # Save packet history
    packet_history.append(packet)

    # Keep only last 100 packets
    if len(packet_history) > 100:
        packet_history.pop(0)

    # -------------------------
    # Large Packet Detection
    # -------------------------
    if packet["length"] > 1400:
        alerts.append("Large Packet Detected")

    # -------------------------
    # Suspicious Protocol
    # -------------------------
    if packet["protocol"] == "OTHER":
        alerts.append("Unknown Protocol")

    # -------------------------
    # DNS Flood Detection
    # -------------------------
    dns = sum(
        1 for p in packet_history
        if p["protocol"] == "DNS"
    )

    if dns > 30:
        alerts.append("Possible DNS Flood")

    # -------------------------
    # HTTPS Flood
    # -------------------------
    https = sum(
        1 for p in packet_history
        if p["protocol"] == "HTTPS"
    )

    if https > 60:
        alerts.append("Heavy HTTPS Traffic")

    # -------------------------
    # Single IP Flood
    # -------------------------
    src_ips = Counter(
        p["src"] for p in packet_history
    )

    for ip, count in src_ips.items():

        if count > 40:
            alerts.append(
                f"High Traffic from {ip}"
            )

    return list(set(alerts))