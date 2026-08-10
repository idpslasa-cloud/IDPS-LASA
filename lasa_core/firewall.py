# lasa_core/firewall.py (Improved with persistence)
import subprocess
import json
import os
from pathlib import Path

DATA_DIR = Path("lasa_data")
DATA_DIR.mkdir(exist_ok=True)
BLOCKED_FILE = DATA_DIR / "blocked_ips.json"
PERM_BAN_FILE = DATA_DIR / "permanent_bans.json"

blocked_ips = set()
permanent_bans = set()

def load_blocks():
    global blocked_ips, permanent_bans
    if BLOCKED_FILE.exists():
        with open(BLOCKED_FILE) as f:
            blocked_ips = set(json.load(f))
    if PERM_BAN_FILE.exists():
        with open(PERM_BAN_FILE) as f:
            permanent_bans = set(json.load(f))
    apply_all_rules()

def apply_all_rules():
    for ip in blocked_ips | permanent_bans:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)

def block_ip(ip):
    if ip not in blocked_ips and ip not in permanent_bans:
        print(f"[FIREWALL] Blocking {ip}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        blocked_ips.add(ip)
        save_blocks()

def add_permanent_ban(ip):
    if ip not in permanent_bans:
        print(f"[FIREWALL] Permanent ban for {ip}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        permanent_bans.add(ip)
        save_blocks()

def unblock_ip(ip):
    blocked_ips.discard(ip)
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    save_blocks()

def remove_permanent_ban(ip):
    permanent_bans.discard(ip)
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    save_blocks()

def reset_firewall():
    print("[FIREWALL] Resetting firewall rules")
    subprocess.run(["sudo", "iptables", "-F"])
    blocked_ips.clear()
    permanent_bans.clear()
    BLOCKED_FILE.unlink(missing_ok=True)
    PERM_BAN_FILE.unlink(missing_ok=True)

def save_blocks():
    with open(BLOCKED_FILE, 'w') as f:
        json.dump(list(blocked_ips), f)
    with open(PERM_BAN_FILE, 'w') as f:
        json.dump(list(permanent_bans), f)

def get_blocked_ips():
    return list(blocked_ips)

def get_permanent_bans():
    return list(permanent_bans)

load_blocks()  # Load on import

