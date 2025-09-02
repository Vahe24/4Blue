#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo privileges."
  exit
fi

echo "--- Starting 4Blue Installer ---"
sleep 1

echo "[+] Updating package list..."
apt-get update

echo "[+] Installing system utilities and Python libraries..."
apt-get install -y python3 python3-pip whois dnsutils curl whatweb ffuf nmap traceroute openssl python3-rich python3-questionary subfinder python3-dnspython python3-requests

echo "[+] Installing 4Blue as a system command..."
chmod +x 4blue_main.py
cp 4blue_main.py /usr/local/bin/4blue

echo ""
echo "--- Installation Complete! ---"
echo "Just type '4blue' in your terminal to run the tool."
