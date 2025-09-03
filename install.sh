#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo privileges."
  exit
fi

echo "--- Starting 4Blue Universal Installer ---"
sleep 1


if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect operating system."
    exit 1
fi


if [[ "$OS" == "kali" || "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "parrot" ]]; then
    echo "[+] Detected Debian-based OS. Using apt..."
    apt-get update
    apt-get install -y python3 python3-pip whois dnsutils curl whatweb ffuf nmap traceroute openssl python3-rich python3-dnspython python3-requests
elif [ "$OS" == "fedora" ]; then
    echo "[+] Detected Fedora. Using dnf..."
    # Имена пакетов для Fedora (например, 'bind-utils' вместо 'dnsutils')
    dnf install -y python3 python3-pip whois bind-utils curl whatweb ffuf nmap traceroute openssl python3-rich python3-dnspython python3-requests
else
    echo "Unsupported operating system: $OS"
    echo "Please install the following dependencies manually: python3, pip, whois, dig, curl, whatweb, ffuf, nmap, traceroute, openssl, rich, dnspython, requests"
    exit 1
fi


echo "[+] Locating Python's site-packages directory..."
SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")
if [ -z "$SITE_PACKAGES" ]; then
    echo "Could not find site-packages directory. Exiting."
    exit 1
fi
rm -rf "$SITE_PACKAGES/blue_tool"
cp -r blue_tool "$SITE_PACKAGES/"

echo "[+] Installing 4Blue as a system command..."
chmod +x 4blue
cp 4blue /usr/local/bin/4blue

echo ""
echo "--- Installation Complete! ---"
echo "Just type '4blue' in your terminal to run the tool."