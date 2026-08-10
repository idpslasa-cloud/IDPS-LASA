from scapy.all import sniff

print("Waiting for packets...")

def show(pkt):
    print(pkt.summary())

sniff(
    iface="enp0s3",
    filter="arp or ip",
    store=False,
    prn=_process_packet
)
