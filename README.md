# 🔱 4Blue Recon Tool
![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.1-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-black?style=for-the-badge&logo=kalilinux)

A powerful and user-friendly TUI tool designed to automate reconnaissance and web application analysis tasks.

<br>

## 📸 Screenshots

<table>
  <tr>
    <td><img width="480"  alt="Screenshot 1" src="https://github.com/user-attachments/assets/c99880a0-d746-4493-8758-2de891d424fb"></td>
    <td><img width="480"  alt="Screenshot 2" src="https://github.com/user-attachments/assets/5ba7e821-189d-4d20-8122-3256505404be"></td>
  </tr>
  <tr>
    <td><img width="480"   alt="Screenshot 3" src="https://github.com/user-attachments/assets/b6ba36ec-8cc4-48dd-9ec4-ab3086934e3f"></td>
    <td><img width="480"  alt="Screenshot 4" src="https://github.com/user-attachments/assets/9a6249ad-d475-43d4-a0a9-8ae4f934e3fd"></td>
  </tr>
   <tr>
    <td><img width="480"   alt="Screenshot 3" src="https://github.com/user-attachments/assets/a9c867d0-7a83-41e0-90f5-ca0cb5c6519b"></td>
    <td><img width="480"  alt="Screenshot 4" src="https://github.com/user-attachments/assets/1a1a670c-ae2f-4cc4-bc18-5fcec8ad05a7"></td>
  </tr>
</table>



## 📖 About The Project

**4Blue** is a command-line interface (CLI) tool written in Python that integrates 15 of the most essential utilities for information gathering into one convenient and interactive interface. It was created to accelerate the initial phases of penetration testing and security analysis by providing all necessary information "under the hood" and presenting it in a clean, readable format.

The core idea is to leverage the power of existing, time-tested tools (`Nmap`, `subfinder`, `ffuf`, etc.) by managing them through a single control center.The entire interface is fully localized in both English and Russian.

## ✨ Features

* **15 Tools in One**: A comprehensive suite for reconnaissance and analysis.
* **Interactive TUI**: User-friendly and intuitive interface for tool selection.
* **Beautiful Output**: Scan results are formatted into tables and panels for easy readability.
* **Multilingual Support**: Available in English and Russian.
* **Simple Installation**: A single script to install all dependencies.
* **Integrated Help**: Descriptions for each tool are accessible directly within the program.
* **Export to HTML**: Don't lose your findings. After every scan, you can choose to export the full, colored output to an HTML file for your records.
 
### Included Tools:

####  Reconnaissance & Information Gathering
* WHOIS Lookup
* DNS Records
* Port Scan (Nmap)
* Traceroute
* GeoIP Location
* SSL/TLS Scan
* Subdomain Enumeration
* TXT Records

#### Web Application Analysis
* HTTP Headers
* Cookies Analyzer
* Tech & CMS Detection
* Robots.txt Analyzer

#### Vulnerability Scanning
* VirusTotal Scan
* Subdomain Takeover
* Content Discovery

## 🛠️ Technology Stack

* **Language**: Python 3
* **Interface (TUI)**: `rich`, `questionary`
* **Networking**: `dnspython`, `requests`
* **Underlying Tools**: `Nmap`, `subfinder`, `ffuf`, `whatweb`, `dig`, `whois`, `curl`, `traceroute`, `openssl`.

## 🚀 Installation & Usage

This tool is designed for use on **Debian-based** systems (Kali Linux, Ubuntu).

### 1. Clone the repository
Replace `your-username` with your GitHub username.
```bash
git clone https://github.com/Vahe24/4Blue.git
```

### 2\. Navigate to the project directory

```bash
cd 4blue
```

### 3\. Make the installer executable

```bash
chmod +x install.sh
```

### 4\. Run the installer

The script will automatically install all necessary utilities and libraries.

```bash
sudo ./install.sh
```

## 💻 How to Use

After installation, you can run the tool from any directory by simply typing the command in your terminal. For scans requiring elevated privileges (e.g., Nmap OS Scan), run with `sudo`.

```bash
# Normal execution
4blue

# Execution for OS detection scans
sudo 4blue
```

Then, just follow the on-screen menu: select your language, choose the desired tool, enter the target, and view the results.

## ⚠️ Disclaimer

This tool is intended for educational and ethical use only. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
