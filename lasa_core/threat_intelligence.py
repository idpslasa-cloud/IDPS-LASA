# lasa_core/threat_intelligence.py (Updated)
def analyse_threat(event_type, source_ip):
    threats = {
        "icmp_flood": {"risk": "HIGH", "explanation": f"ICMP flood from {source_ip}. DoS attempt.", "action": "Blocked"},
        "port_scan": {"risk": "MEDIUM", "explanation": f"Port scan from {source_ip}. Reconnaissance.", "action": "Permanent ban"},
        "arp_spoofing": {"risk": "CRITICAL", "explanation": f"ARP spoofing/MitM from {source_ip}!", "action": "Permanent ban"},
        "arp_scanning": {"risk": "HIGH", "explanation": f"ARP scanning from {source_ip}. Network recon.", "action": "Blocked"},
    }
    return threats.get(event_type, {"risk": "LOW", "explanation": "Unknown", "action": "Monitor"})

