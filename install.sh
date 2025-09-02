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
apt-get install -y python3 python3-pip whois dnsutils curl whatweb ffuf nmap traceroute openssl python3-rich python3-questionary python3-dnspython python3-requests


echo "[+] Locating Python's site-packages directory..."

SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")

if [ -z "$SITE_PACKAGES" ]; then
    echo "Could not find site-packages directory. Exiting."
    exit 1
fi
echo "Found: $SITE_PACKAGES"

echo "[+] Installing 4Blue package into system libraries..."

rm -rf "$SITE_PACKAGES/blue_tool"
cp -r blue_tool "$SITE_PACKAGES/"

echo "[+] Installing 4Blue as a system command..."
chmod +x 4blue
cp 4blue /usr/local/bin/4blue

echo ""
echo "--- Installation Complete! ---"
echo "Just type '4blue' in your terminal to run the tool."

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
