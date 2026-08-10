# lasa_core/ids_detector.py (Enhanced ARP spoofing & scanning detection) [web:1][web:5][web:9]
import datetime
import threading
import time
from collections import defaultdict, deque

from scapy.all import sniff, conf, IP, TCP, ICMP, ARP, Ether
from scapy.layers.l2 import ARP as ARP_LAYER

from lasa_core.firewall import block_ip, add_permanent_ban, unblock_ip, remove_permanent_ban
from lasa_core.trusted_devices import TRUSTED_DEVICES
from lasa_core.threat_intelligence import analyse_threat

# Storage
arp_table = {}  # ip -> mac (legitimate mapping)
arp_history = {}  # ip -> deque of (mac, timestamp)
arp_packet_counter = defaultdict(int)
arp_scan_counter = defaultdict(int)  # Broadcast ARPs for scanning
arp_spoof_attempts = defaultdict(int)

icmp_counter = defaultdict(int)
portscan_counter = defaultdict(set)
packet_counter = defaultdict(int)

alerts = deque(maxlen=200)  # Recent alerts
ids_running = False
CURRENT_NETWORK = None
LOCAL_IP = "10.0.2.15"  # Make configurable

TRUSTED_SERVERS = ["8.8.8.8", "1.1.1.1"]

# Thresholds
ICMP_THRESHOLD = 20
PORTSCAN_THRESHOLD = 30
ARP_FLOOD_THRESHOLD = 50
ARP_SCAN_THRESHOLD = 20  # Lower for broadcasts [web:2]
ARP_SPOOF_THRESHOLD = 3  # Multiple MACs for same IP
TRAFFIC_ANOMALY_THRESHOLD = 300

def add_alert(message, threat_type="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] [{threat_type}] {message}"
    print(formatted)
    alerts.append(formatted)

def check_network_change(ip):
    global CURRENT_NETWORK
    network = ".".join(ip.split(".")[:3])
    if CURRENT_NETWORK is None:
        CURRENT_NETWORK = network
    elif CURRENT_NETWORK != network:
        add_alert("Network changed. Resetting ARP table.", "INFO")
        arp_table.clear()
        CURRENT_NETWORK = network

def get_true_mac(ip):
    """Active probe to verify real MAC [web:1][web:5]"""
    try:
        from scapy.all import ARP, Ether, srp
        arp_req = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = srp(broadcast/arp_req, timeout=2, verbose=False)[0]
        return answered[0][1].hwsrc if answered else None
    except:
        return None

def detect_arp_spoof(packet):
    if ARP not in packet:
        return

    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    dst_ip = packet[ARP].pdst
    op = packet[ARP].op  # 1=request, 2=reply

    check_network_change(src_ip)
    arp_packet_counter[src_ip] += 1
    arp_scan_counter[src_ip] += 1

    # Detect ARP scanning: many requests to different/broadcast dst [web:2][web:6]
    if op == 1 and (dst_ip == "0.0.0.0" or dst_ip.startswith("255.255.255.")):
        if arp_scan_counter[src_ip] > ARP_SCAN_THRESHOLD:
            threat = analyse_threat("arp_scanning", src_ip)
            add_alert(f"ARP Scan detected from {src_ip}: {threat['explanation']}", "ALERT")
            block_ip(src_ip)
    elif op == 1:  # Normal request
        arp_scan_counter[src_ip] += 0.5  # Partial count

    # ARP Flood
    if arp_packet_counter[src_ip] > ARP_FLOOD_THRESHOLD:
        add_alert(f"ARP flood from {src_ip}", "WARNING")
        block_ip(src_ip)

    # Trusted device check
    if src_ip in TRUSTED_DEVICES:
        if TRUSTED_DEVICES[src_ip] != src_mac:
            threat = analyse_threat("arp_spoofing", src_ip)
            add_alert(f"Trusted device MAC mismatch {src_ip}: {threat['explanation']}", "CRITICAL")
            add_permanent_ban(src_ip)
            return

    # Maintain history for IP->multiple MACs detection [web:9]
    if src_ip not in arp_history:
        arp_history[src_ip] = deque(maxlen=10)
    arp_history[src_ip].append((src_mac, time.time()))

    # First seen
    if src_ip not in arp_table:
        arp_table[src_ip] = src_mac
        add_alert(f"New device: {src_ip} -> {src_mac}", "INFO")
        return

    # Spoof detection: different MAC for known IP
    if arp_table[src_ip] != src_mac:
        arp_spoof_attempts[src_ip] += 1
        add_alert(f"Spoof attempt on {src_ip}: claimed {src_mac}, expected {arp_table[src_ip]}", "ALERT")

        # Verify with active probe
        true_mac = get_true_mac(src_ip)
        if true_mac and true_mac != src_mac:
            threat = analyse_threat("arp_spoofing", src_ip)
            add_alert(f"Confirmed ARP spoofing {src_ip}! True MAC: {true_mac}", "CRITICAL")
            add_permanent_ban(src_ip)
            return

        if arp_spoof_attempts[src_ip] > ARP_SPOOF_THRESHOLD:
            add_permanent_ban(src_ip)

        # Unsolicited replies
        if op == 2 and dst_ip == "0.0.0.0":
            add_alert(f"Unsolicited ARP reply from {src_ip}", "WARNING")

    # Detect if OURSELF being scanned/spoofed (incoming targeted)
    if dst_ip == LOCAL_IP:
        add_alert(f"ARP targeted at local host {LOCAL_IP} from {src_ip}", "WARNING")

def analyse_packet(packet):
    detect_arp_spoof(packet)

    if IP not in packet or packet[IP].src == LOCAL_IP:
        return

    src_ip = packet[IP].src
    packet_counter[src_ip] += 1

    if any(s in src_ip for s in ["104.18", "8.8.8", "1.1"]):
        return

    if packet_counter[src_ip] > TRAFFIC_ANOMALY_THRESHOLD:
        add_alert(f"Traffic anomaly from {src_ip}", "WARNING")

    if ICMP in packet:
        icmp_counter[src_ip] += 1
        if icmp_counter[src_ip] > ICMP_THRESHOLD:
            add_alert(f"ICMP flood from {src_ip}", "ALERT")
            block_ip(src_ip)

    if TCP in packet:
        dport = packet[TCP].dport
        portscan_counter[src_ip].add(dport)
        if len(portscan_counter[src_ip]) > PORTSCAN_THRESHOLD:
            add_alert(f"Port scan from {src_ip}", "ALERT")
            add_permanent_ban(src_ip)

def reset_counters():
    while ids_running:
        time.sleep(60)  # Reset every minute
        icmp_counter.clear()
        portscan_counter.clear()
        packet_counter.clear()
        arp_packet_counter.clear()
        arp_scan_counter.clear()

def start_ids():
    sniff(iface=conf.iface, prn=analyse_packet, store=False, filter="arp or ip")

def start_sniffer():
    global ids_running
    if not ids_running:
        threading.Thread(target=reset_counters, daemon=True).start()
        threading.Thread(target=start_ids, daemon=True).start()
        ids_running = True
        add_alert("LASA IDS Started", "INFO")

def stop_sniffer():
    global ids_running
    ids_running = False
    add_alert("LASA IDS Stopped", "INFO")

def get_status():
    return {"running": ids_running, "network": CURRENT_NETWORK}

def get_recent_alerts():
    return list(alerts)

def get_arp_table():
    return dict(arp_table)

