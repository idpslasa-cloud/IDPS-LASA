def analyse_threat(event_type, source_ip):
    if event_type == "icmp_flood":
        return {
            "risk": "HIGH",
            "explanation": (
                f"High volume traffic detected from {source_ip}.\n"
                "Possible denial-of-service attempt."
            ),
            "action": "Block source IP immediately",
        }
    elif event_type == "port_scan":
        return {
            "risk": "MEDIUM",
            "explanation": (
                f"Multiple ports probed by {source_ip}.\n"
                "Possible reconnaissance activity."
            ),
            "action": "Block source IP immediately",
        }
    elif event_type == "arp_spoofing":
        return {
            "risk": "CRITICAL",
            "explanation": (
                f"MAN-IN-THE-MIDDLE ATTACK DETECTED!\n"
                f"ARP spoofing from {source_ip}.\n"
                "Attacker is poisoning ARP cache to intercept traffic."
            ),
            "action": "EMERGENCY BLOCK - Permanent ban applied",
        }
    else:
        return {
            "risk": "LOW",
            "explanation": "No abnormal behaviour detected",
            "action": "No action required",
        }

