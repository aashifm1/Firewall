#!/bin/bash
echo "[*] Setting iptables rules..."
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
echo "[*] Done. Run firewall.py with sudo."
