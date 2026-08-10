from scapy.all import sniff

def detect_packet(packet):
    print("Packet detected:", packet.summary())

def start_monitor():
    print("Starting network monitoring...")
    sniff(prn=detect_packet, store=False)
