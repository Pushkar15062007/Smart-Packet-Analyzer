from scapy.all import TCP, UDP, ICMP


def protocol_name(packet):
    """
    Returns a readable protocol name.
    """

    if packet.haslayer(TCP):

        if packet[TCP].sport == 443 or packet[TCP].dport == 443:
            return "HTTPS"

        elif packet[TCP].sport == 80 or packet[TCP].dport == 80:
            return "HTTP"

        else:
            return "TCP"

    elif packet.haslayer(UDP):

        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            return "DNS"

        else:
            return "UDP"

    elif packet.haslayer(ICMP):
        return "ICMP"

    return "OTHER"