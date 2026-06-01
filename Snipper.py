# ============================================================
#   NETWORK SNIFFER - Simple Version
#   Tool: Python + Scapy
#   What it does: Captures network packets and shows info
# ============================================================

from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
from collections import defaultdict

# ── Global counters ─────────────────────────────────────────
all_packets   = []          # stores every packet we capture
stats         = defaultdict(int)  # counts TCP, UDP, ICMP
total         = 0           # total packet count


# ── Helper: get protocol name ───────────────────────────────
def get_protocol(num):
    # IP header stores protocol as a number. We convert it.
    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return names.get(num, "OTHER")


# ── Helper: get port numbers ────────────────────────────────
def get_ports(packet):
    # TCP and UDP packets have port numbers. ICMP does not.
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    return "N/A", "N/A"


# ── Helper: read the payload (actual data inside packet) ────
def get_payload(packet):
    if packet.haslayer(Raw):
        # Raw bytes → readable text. Replace weird chars with ?
        return packet[Raw].load.decode("ascii", errors="replace")[:60]
    return "No data"


# ── Main function: called automatically for EVERY packet ────
def handle_packet(packet):
    global total

    # Skip non-IP packets (like ARP)
    if not packet.haslayer(IP):
        return

    total += 1
    all_packets.append(packet)

    # Pull out the basic info
    src     = packet[IP].src
    dst     = packet[IP].dst
    proto   = get_protocol(packet[IP].proto)
    s_port, d_port = get_ports(packet)
    payload = get_payload(packet)
    time    = datetime.now().strftime("%H:%M:%S")

    # Update stats counter
    stats[proto] += 1

    # Print it nicely
    print(f"\n[#{total}] {time}")
    print(f"  Protocol : {proto}")
    print(f"  From     : {src}:{s_port}")
    print(f"  To       : {dst}:{d_port}")
    print(f"  Data     : {payload}")
    print("  " + "-" * 45)


# ── Show summary when done ──────────────────────────────────
def show_summary():
    print("\n\n========== CAPTURE SUMMARY ==========")
    print(f"Total packets : {total}")
    print(f"PCAP saved to : captured.pcap")
    print("\nProtocol Breakdown:")
    for proto, count in stats.items():
        pct = round(count / total * 100, 1) if total > 0 else 0
        bar = "#" * int(pct / 5)
        print(f"  {proto:<6} {count:>4} packets  {pct}%  {bar}")
    print("=====================================\n")


# ── START ───────────────────────────────────────────────────
if __name__ == "__main__":

    print("=" * 50)
    print("       BASIC NETWORK SNIFFER")
    print("       Press CTRL+C to stop")
    print("=" * 50)

    # Ask user which interface to use
    iface = input("\nEnter interface (e.g. eth0 / wlan0) or ENTER for auto: ").strip()
    if iface == "":
        iface = None

    # Ask how many packets
    count_str = input("How many packets? (0 = unlimited): ").strip()
    count = int(count_str) if count_str.isdigit() else 0

    print("\n[*] Sniffing started... open a browser to see packets!\n")

    try:
        # sniff() captures packets and calls handle_packet() for each one
        sniff(iface=iface, prn=handle_packet, count=count, store=False)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

    except PermissionError:
        print("\n[!] ERROR: Run with sudo (Linux) or as Administrator (Windows)")

    finally:
        # Save packets to file and show stats — always runs at the end
        if all_packets:
            wrpcap("captured.pcap", all_packets)
        show_summary()
