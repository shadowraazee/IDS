from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP
import time

# CONFIGURATION
BLOCKED_IPS = set()
SYN_THRESHOLD = 20        # SYN packets per time window
TIME_WINDOW = 5           # seconds
PORT_SCAN_THRESHOLD = 10  # unique ports

# Tracking structures
syn_counts = {}
port_scan_tracker = {}

# HELPER FUNCTIONS

def detect_syn_flood(src_ip):
    now = time.time()
    syn_counts.setdefault(src_ip, [])
    syn_counts[src_ip] = [t for t in syn_counts[src_ip] if now - t < TIME_WINDOW]
    syn_counts[src_ip].append(now)

    if len(syn_counts[src_ip]) > SYN_THRESHOLD:
        print(f"[ALERT] SYN flood detected from {src_ip}")
        BLOCKED_IPS.add(src_ip)
        return True
    return False


def detect_port_scan(src_ip, dst_port):
    now = time.time()
    port_scan_tracker.setdefault(src_ip, {})
    ports = port_scan_tracker[src_ip]

    # Clean old entries
    ports = {p: t for p, t in ports.items() if now - t < TIME_WINDOW}
    ports[dst_port] = now
    port_scan_tracker[src_ip] = ports

    if len(ports) > PORT_SCAN_THRESHOLD:
        print(f"[ALERT] Port scan detected from {src_ip}")
        BLOCKED_IPS.add(src_ip)
        return True
    return False


# MAIN PACKET PROCESSOR

def process_packet(packet):
    pkt = IP(packet.get_payload())

    src_ip = pkt.src
    dst_ip = pkt.dst

    #Blocked
    if src_ip in BLOCKED_IPS:
        print(f"[BLOCKED] Dropping packet from {src_ip}")
        packet.drop()
        return

    #TCP analysis
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]

        #SYN packet detection
        if tcp.flags == "S":
            if detect_syn_flood(src_ip):
                packet.drop()
                return

            if detect_port_scan(src_ip, tcp.dport):
                packet.drop()
                return

    #UDP basic logging (optional)
    elif pkt.haslayer(UDP):
        print(f"[INFO] UDP Packet {src_ip} → {dst_ip}")

    packet.accept()


# RUN

def main():
    print("[*] Starting IDS/IPS...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process_packet)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping IPS...")
        nfqueue.unbind()


if __name__ == "__main__":
    main()