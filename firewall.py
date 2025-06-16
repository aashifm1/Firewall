from scapy.all import IP, TCP, ICMP
from netfilterqueue import NetfilterQueue
import logging
import json

# Load firewall rules from external JSON
RULES_FILE = "Rules.json"

# Setup logging
logging.basicConfig(filename="logs/firewall.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def stealth(packet, rules):
    ip = IP(packet.payload())

    # Block ICMP
    if ip.haslayer(ICMP) and rules.get("block_icmp", False):
        return True

    # Block specified TCP ports
    if ip.haslayer(TCP):
        tcp = ip[TCP]
        if tcp.dport in rules.get("blocked_ports", []) and tcp.flags == "S":
            return True

    return False

def processpacket(packet):
    rules = rules()
    if stealth(packet, rules):
        ip = IP(packet.payload())
        logging.info(f"Dropped: {ip.src} -> {ip.dst} [{ip.proto}]")
        packet.drop()
    else:
        packet.accept()

def main():
    print("[*] Stealth Firewall Starting...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, processpacket)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("[!] Exiting...")
        nfqueue.unbind()

if __name__ == "__main__":
    main()
