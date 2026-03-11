import datetime
import threading
import time
from collections import defaultdict

from scapy.all import sniff, conf, IP, TCP, ICMP, ARP

from lasa_core.firewall import block_ip, add_permanent_ban, reset_firewall
from lasa_core.trusted_devices import TRUSTED_DEVICES


# -----------------------------
# STORAGE
# -----------------------------

arp_table = {}
arp_change_counter = defaultdict(int)
arp_packet_counter = defaultdict(int)
arp_scan_counter = defaultdict(int)

icmp_counter = defaultdict(int)
portscan_counter = defaultdict(set)
packet_counter = defaultdict(int)
mac_change_counter = defaultdict(int)

alerts = []

ids_running = False
CURRENT_NETWORK = None


# -----------------------------
# THRESHOLDS
# -----------------------------

ICMP_THRESHOLD = 20
PORTSCAN_THRESHOLD = 30
ARP_FLOOD_THRESHOLD = 50
ARP_SCAN_THRESHOLD = 40
TRAFFIC_ANOMALY_THRESHOLD = 300


# -----------------------------
# WHITELIST / IGNORE
# -----------------------------

LOCAL_IP = "10.0.2.15"

TRUSTED_SERVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "104.18.0.0",
]


# -----------------------------
# ALERT HANDLING
# -----------------------------

def add_alert(message):

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {message}"

    print(formatted)

    alerts.append(formatted)

    if len(alerts) > 100:
        alerts.pop(0)


# -----------------------------
# NETWORK CHANGE CHECK
# -----------------------------

def check_network_change(ip):

    global CURRENT_NETWORK

    network = ".".join(ip.split(".")[:3])

    if CURRENT_NETWORK is None:
        CURRENT_NETWORK = network

    elif CURRENT_NETWORK != network:

        add_alert("[INFO] Network changed. Resetting ARP table.")

        arp_table.clear()

        CURRENT_NETWORK = network


# -----------------------------
# ARP DETECTION
# -----------------------------

def detect_arp_spoof(packet):

    if ARP not in packet:
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    target = packet[ARP].pdst

    check_network_change(ip)

    arp_packet_counter[ip] += 1
    arp_scan_counter[ip] += 1


    # ARP FLOOD
    if arp_packet_counter[ip] > ARP_FLOOD_THRESHOLD:

        add_alert(f"[WARNING] ARP flood detected from {ip}")


    # ARP SCAN
    if arp_scan_counter[ip] > ARP_SCAN_THRESHOLD:

        add_alert(f"[ALERT] Possible ARP scan from {ip}")


    # TRUSTED DEVICE VALIDATION
    if ip in TRUSTED_DEVICES:

        if TRUSTED_DEVICES[ip] != mac:

            add_alert(f"[CRITICAL] Trusted device MAC mismatch for {ip}")

            block_ip(ip)
            add_permanent_ban(ip)

            return


    # FIRST TIME DEVICE
    if ip not in arp_table:

        arp_table[ip] = mac
        return


    # MAC CHANGE DETECTION
    if arp_table[ip] != mac:

        arp_change_counter[ip] += 1
        mac_change_counter[ip] += 1

        add_alert(f"[ALERT] Possible ARP spoofing: {ip} changed MAC")

        if mac_change_counter[ip] > 5:

            add_alert(f"[CRITICAL] MAC randomization attack from {ip}")

            block_ip(ip)
            add_permanent_ban(ip)


    # UNSOLICITED ARP REPLY
    if packet[ARP].op == 2 and target == "0.0.0.0":

        add_alert(f"[WARNING] Suspicious ARP reply from {ip}")


# -----------------------------
# PACKET ANALYSIS
# -----------------------------

def analyse_packet(packet):

    detect_arp_spoof(packet)

    if IP not in packet:
        return

    src_ip = packet[IP].src


    # IGNORE LOCAL MACHINE
    if src_ip == LOCAL_IP:
        return


    # IGNORE TRUSTED INTERNET SERVERS
    if src_ip.startswith("104.18"):
        return


    packet_counter[src_ip] += 1


    # TRAFFIC ANOMALY
    if packet_counter[src_ip] > TRAFFIC_ANOMALY_THRESHOLD:

        add_alert(f"[WARNING] Abnormal traffic rate from {src_ip}")


    # ICMP FLOOD
    if ICMP in packet:

        icmp_counter[src_ip] += 1

        if icmp_counter[src_ip] > ICMP_THRESHOLD:

            add_alert(f"[ALERT] ICMP Flood detected from {src_ip}")

            block_ip(src_ip)


    # PORT SCAN
    if TCP in packet:

        dport = packet[TCP].dport if hasattr(packet[TCP], "dport") else None

        if dport:

            portscan_counter[src_ip].add(dport)

            if len(portscan_counter[src_ip]) > PORTSCAN_THRESHOLD:

                add_alert(f"[ALERT] Port Scan detected from {src_ip}")

                add_permanent_ban(src_ip)


# -----------------------------
# COUNTER RESET SYSTEM
# -----------------------------

def reset_counters():

    while True:

        time.sleep(30)

        packet_counter.clear()
        icmp_counter.clear()
        arp_packet_counter.clear()
        arp_scan_counter.clear()
        portscan_counter.clear()


# -----------------------------
# IDS START
# -----------------------------

def start_ids():

    sniff(
        iface=conf.iface,
        prn=analyse_packet,
        store=False,
        filter="ip or arp"
    )


def start_sniffer():

    global ids_running

    if not ids_running:

        thread = threading.Thread(target=start_ids, daemon=True)
        thread.start()

        reset_thread = threading.Thread(target=reset_counters, daemon=True)
        reset_thread.start()

        ids_running = True


# -----------------------------
# STATUS API
# -----------------------------

def get_status():
    return "Running" if ids_running else "Stopped"


def get_recent_alerts():
    return alerts[-10:]


def reset_blocks():

    reset_firewall()

    alerts.clear()
