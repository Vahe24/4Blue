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


echo "[+] Installing system utilities via package manager..."
if [[ "$OS" == "kali" || "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "parrot" ]]; then
    apt-get update
   
    apt-get install -y python3 python3-pip whois dnsutils curl whatweb ffuf nmap traceroute openssl python3-rich python3-dnspython python3-requests
elif [ "$OS" == "fedora" ]; then
    dnf install -y python3 python3-pip whois bind-utils curl whatweb ffuf nmap traceroute openssl python3-rich python3-dnspython python3-requests
elif [ "$OS" == "arch" ]; then
    pacman -Syu --noconfirm python python-pip whois bind curl whatweb ffuf nmap traceroute openssl python-rich python-dnspython python-requests
else
    echo "Unsupported OS for automatic dependency installation: $OS"
    exit 1
fi


echo "[+] Installing 'questionary' using pip..."
pip3 install questionary --break-system-packages


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