import subprocess

blocked_ips = set()
permanent_bans = set()


# -----------------------------
# BLOCK IP
# -----------------------------
def block_ip(ip):

    if ip not in blocked_ips:

        print(f"[FIREWALL] Blocking {ip}")

        subprocess.run([
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP"
        ])

        blocked_ips.add(ip)


# -----------------------------
# PERMANENT BAN
# -----------------------------
def add_permanent_ban(ip):

    if ip not in permanent_bans:

        print(f"[FIREWALL] Permanent ban for {ip}")

        subprocess.run([
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP"
        ])

        permanent_bans.add(ip)


# -----------------------------
# RESET FIREWALL
# -----------------------------
def reset_firewall():

    print("[FIREWALL] Resetting firewall rules")

    subprocess.run(["sudo", "iptables", "-F"])

    blocked_ips.clear()
    permanent_bans.clear()


# -----------------------------
# GET BLOCKED IPS
# -----------------------------
def get_blocked_ips():
    return list(blocked_ips)


# -----------------------------
# GET PERMANENT BANS
# -----------------------------
def get_permanent_bans():
    return list(permanent_bans)
