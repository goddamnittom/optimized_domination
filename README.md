A high-performance, multi-vector local network denial-of-service (DoS) attack script designed to completely overwhelm and disable a consumer-grade router (or any gateway device) on the same LAN.
What it does – step by step:

Auto-detects your network
Finds the default gateway IP (your router, e.g. 192.168.1.1)
Calculates the correct broadcast address (e.g. 192.168.1.255)
Identifies the active network interface

Launches 8 simultaneous, optimized attack vectors (all running in parallel threads):
ARP Poison: Floods fake ARP replies to corrupt the router's MAC table and disrupt local traffic routing
SYN Flood: Sends massive spoofed TCP SYN packets to exhaust the router's connection state table
UDP Flood: Blasts large random UDP packets to common and random ports to saturate bandwidth and CPU
ICMP Smurf: Spoofs ICMP Echo Requests from the router's IP to the broadcast address → every device on the LAN replies to the router, amplifying the flood 10–100x
SSDP Amplification: Sends spoofed UPnP M-SEARCH requests to broadcast, triggering huge responses from IoT devices back to the router
Fraggle Attack: Classic UDP broadcast flood (echo/chargen style) spoofed from router IP
DNS Amplification: Spoofs large DNS ANY queries to broadcast if open resolvers exist
TCP ACK/RST Storm: Floods bogus ACK and RST packets to corrupt existing connections and fill state tables

Extreme efficiency optimizations
Uses Scapy's batch sending (count=150–400 per loop) → millions of packets per second
Pre-generated random IP pool (10,000 entries) to eliminate overhead in hot loops
No delays, no per-packet prints → maximum throughput, minimal CPU usage on attacker machine
Fewer threads needed for same or greater impact than traditional tools


Result on target router:

CPU spikes to 100% instantly
Connection table overflows
Packet queue backlog → all legitimate traffic dropped
Most home routers reboot, lock up, or enter bootloop within 10–60 seconds
WiFi and wired clients lose connectivity completely

Usage example:
sudo python3 optimized_domination.py -i wlan0 -t 800
