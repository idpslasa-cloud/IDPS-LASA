"""
Unified detection engine: wraps arp_detect + scanflood logic.
Writes alerts to Django DB via direct SQLite write (simple approach)
and pushes packets into an asyncio Queue for WebSocket broadcast.
"""
"""
Unified detection engine: wraps arp_detect + scanflood logic.
Writes alerts to Django DB via direct SQLite write (simple approach)
and pushes packets into an asyncio Queue for WebSocket broadcast.
"""
import subprocess
import asyncio
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, ARP, IP, ICMP, TCP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# Shared state
packet_queue: asyncio.Queue = None
alert_callbacks = []

_loop = None

# Sniffer state
sniffer_started = False          # Has the sniffer thread started?
idps_on = False          # Is IDS detection enabled?
sniffer_thread = None

# ARP
arp_table = {}

# ICMP flood
icmp_tracker = defaultdict(deque)
ICMP_PPS_THRESHOLD = 10

# Port scan
port_tracker = defaultdict(lambda: defaultdict(deque))
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

# Dashboard stats
alert_count = 0
active_threats = 0


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def block_ip(ip, permanent=False):
    """
    Blocks an IP using iptables.
    permanent=False only affects the database flag.
    The actual iptables rule remains until manually removed.
    """

    try:
        # Prevent duplicate rules
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if check.returncode == 0:
            print(f"[BLOCK] {ip} already blocked.")
            return

        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )

        print(f"[BLOCK] {ip} blocked successfully.")

    except Exception as e:
        print(f"[BLOCK ERROR] {e}")


def _emit_alert(attack_type, src_ip, description, dst_ip=None, src_port=None, dst_port=None):
    global alert_count, active_threats
    alert_count += 1
    active_threats += 1
    alert = {
        "attack_type": attack_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "description": description,
        "timestamp": _ts(),
    }
    # Save to Django DB via Django ORM (called from thread — use django.db connection)
    _save_alert_to_db(alert)
    # Notify async callbacks (WebSocket broadcast)
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(_broadcast_alert(alert), _loop)


def _save_alert_to_db(alert):
    try:
        import django
        import os
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "IDPS.settings")
        django.setup()
        from dashboard.models import Alert, BlockedIP
        a = Alert.objects.create(
            attack_type=alert["attack_type"],
            source_ip=alert["source_ip"],
            destination_ip=alert["destination_ip"],
            source_port=alert["source_port"],
            destination_port=alert["destination_port"],
            description=alert["description"],
            status="BLOCKED" if alert["attack_type"] == "ARP_SPOOF" else "ACTIVE",
        )
        # Auto-block ARP permanently, others temporarily
        permanent = alert["attack_type"] == "ARP_SPOOF"
        BlockedIP.objects.get_or_create(
            ip_address=alert["source_ip"],
            defaults={"reason": alert["description"], "permanent": permanent},
        )
        if alert["attack_type"] in ["ARP_SPOOF", "ICMP_FLOOD"]:
            block_ip(alert["source_ip"], permanent=True)
    except Exception as e:
        print(f"[DB] Error saving alert: {e}")


async def _broadcast_alert(alert):
    for cb in alert_callbacks:
        try:
            await cb(alert)
        except Exception:
            pass


def _process_packet(pkt):
    print(f"[PACKET] {pkt.summary()}")
    if not idps_on:
        return
    now = time.time()
    flagged = False
    src_ip = dst_ip = "?"
    src_port = dst_port = None
    protocol = "OTHER"
    size = len(pkt)

    # ── ARP detection ──
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        protocol = "ARP"
        src_ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if src_ip in arp_table and arp_table[src_ip] != mac:
            flagged = True
            _emit_alert("ARP_SPOOF", src_ip,
                        f"ARP spoofing: IP {src_ip} changed MAC from {arp_table[src_ip]} to {mac}")
        else:
            arp_table[src_ip] = mac

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    # ── ICMP flood ──
    if pkt.haslayer(ICMP):
        print(f"[ICMP] Packet from {src_ip} -> {dst_ip}")

        protocol = "ICMP"
        icmp_tracker[src_ip].append(now)

        while icmp_tracker[src_ip] and now - icmp_tracker[src_ip][0] > 1:
            icmp_tracker[src_ip].popleft()

        print(f"[ICMP] Current PPS: {len(icmp_tracker[src_ip])}")

        if len(icmp_tracker[src_ip]) >= ICMP_PPS_THRESHOLD:
            print("[ICMP] FLOOD DETECTED!")
            flagged = True
            _emit_alert(
                "ICMP_FLOOD",
                src_ip,
                f"ICMP flood: {len(icmp_tracker[src_ip])} PPS",
                dst_ip=dst_ip
            )

    # ── Port scan ──
    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        port_tracker[src_ip][dst_port].append(now)
        # Clean old
        for p in list(port_tracker[src_ip]):
            dq = port_tracker[src_ip][p]
            while dq and now - dq[0] > TIME_WINDOW:
                dq.popleft()
            if not dq:
                del port_tracker[src_ip][p]
        if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            flagged = True
            _emit_alert("PORT_SCAN", src_ip,
                        f"Port scan: {len(port_tracker[src_ip])} ports in {TIME_WINDOW}s",
                        dst_ip=dst_ip, dst_port=dst_port)

    pkt_data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": size,
        "timestamp": _ts(),
        "flagged": flagged,
    }

    if packet_queue and _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(packet_queue.put(pkt_data), _loop)


def start_sniffing(loop, queue):
    """
    Starts the Scapy sniffer only once.
    The thread remains alive for the lifetime of FastAPI.
    Packet analysis depends on idps_on.
    """
    global _loop, packet_queue, sniffer_started, sniffer_thread

    _loop = loop
    packet_queue = queue

    if sniffer_started:
        print("[INFO] Sniffer already running.")
        return

    if not SCAPY_OK:
        print("[WARN] Scapy not installed.")
        return

    sniffer_started = True

    sniffer_thread = threading.Thread(
        target=_sniff_thread,
        daemon=True
    )
    sniffer_thread.start()

    print("[INFO] Packet sniffer started.")

def _sniff_thread():
    try:
        print("[INFO] Starting sniffer on enp0s3...")
        sniff(
            iface="enp0s3",
            filter="arp or ip",
            store=False,
            prn=_process_packet
        )
    except PermissionError:
        print(
            "[ERROR] Root privileges are required for packet sniffing."
        )
    except Exception as e:
        print(f"[ERROR] Sniffer stopped: {e}")


def toggle():
    global idps_on

    idps_on = not idps_on

    if idps_on:
        print("[INFO] IDS Enabled")
    else:
        print("[INFO] IDS Disabled")

    return idps_on
import asyncio
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, ARP, IP, ICMP, TCP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# Shared state
packet_queue: asyncio.Queue = None
alert_callbacks = []

_loop = None

# Sniffer state
sniffer_started = False          # Has the sniffer thread started?
idps_on = False          # Is IDS detection enabled?
sniffer_thread = None

# ARP
arp_table = {}

# ICMP flood
icmp_tracker = defaultdict(deque)
ICMP_PPS_THRESHOLD = 10

# Port scan
port_tracker = defaultdict(lambda: defaultdict(deque))
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

# Dashboard stats
alert_count = 0
active_threats = 0


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _emit_alert(attack_type, src_ip, description, dst_ip=None, src_port=None, dst_port=None):
    global alert_count, active_threats
    alert_count += 1
    active_threats += 1
    alert = {
        "attack_type": attack_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "description": description,
        "timestamp": _ts(),
    }
    # Save to Django DB via Django ORM (called from thread — use django.db connection)
    _save_alert_to_db(alert)
    # Notify async callbacks (WebSocket broadcast)
    if _loop and not _loop.is_closed():
        asyncio.run_coroutine_threadsafe(_broadcast_alert(alert), _loop)


async def _broadcast_alert(alert):
    for cb in alert_callbacks:
        try:
            await cb(alert)
        except Exception:
            pass


def start_sniffing(loop, queue):
    """
    Starts the Scapy sniffer only once.
    The thread remains alive for the lifetime of FastAPI.
    Packet analysis depends on idps_on.
    """
    global _loop, packet_queue, sniffer_started, sniffer_thread

    _loop = loop
    packet_queue = queue

    if sniffer_started:
        print("[INFO] Sniffer already running.")
        return

    if not SCAPY_OK:
        print("[WARN] Scapy not installed.")
        return

    sniffer_started = True

    sniffer_thread = threading.Thread(
        target=_sniff_thread,
        daemon=True
    )
    sniffer_thread.start()

    print("[INFO] Packet sniffer started.")

def _sniff_thread():
    try:
        print("[INFO] Starting sniffer on enp0s3...")
        sniff(
            iface="enp0s3",
            filter="arp or ip",
            store=False,
            prn=_process_packet
        )
    except PermissionError:
        print(
            "[ERROR] Root privileges are required for packet sniffing."
        )
    except Exception as e:
        print(f"[ERROR] Sniffer stopped: {e}")


def toggle():
    global idps_on

    idps_on = not idps_on

    if idps_on:
        print("[INFO] IDS Enabled")
    else:
        print("[INFO] IDS Disabled")

    return idps_on
