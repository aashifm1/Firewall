#!/bin/bash
echo "[*] Cleaning iptables rules..."
sudo iptables -D INPUT -j NFQUEUE --queue-num 1
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
echo "[*] Done."
