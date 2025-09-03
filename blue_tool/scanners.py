import os
import subprocess
import socket
import dns.resolver
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def run_command(command, title, target):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, input="", timeout=300)
        return result.stdout.strip()
    except FileNotFoundError:
        console.print(f"\n[bold red]ERROR: Command '{command[0]}' not found. Please run install.sh[/bold red]")
    except subprocess.TimeoutExpired:
        console.print(f"\n[bold red]ERROR: Command timed out for {target}.[/bold red]")
    except subprocess.CalledProcessError as e:
        console.print(f"\n[bold red]ERROR executing command for {target}:[/bold red]\n{e.stderr}")
    return None

def run_whois(target, LANG):
    output = run_command(["whois", target], "WHOIS", target)
    if output:
        return Panel(output, border_style="cyan", title=f"WHOIS Report for {target}")
    return None

def run_dns_records(target, LANG):
    output = run_command(["dig", target, "ANY"], "DNS Records", target)
    if output:
        return Panel(output, border_style="cyan", title=f"DNS Records for {target}")
    return None

def run_port_scan(target, LANG):
    console.print(LANG["nmap_start_scan"].format(target=target))
    console.print(LANG["nmap_wait_message"])
    command = ["sudo", "nmap", "-F", "-sV", "-O", "--open", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()
        if not output and result.stderr:
             return Panel(result.stderr.strip(), border_style="red", title=LANG["nmap_error_title"])

        table = Table(title=LANG["nmap_report_title"].format(target=target), style="blue")
        table.add_column(LANG["nmap_header_port"], style="cyan", width=15)
        table.add_column(LANG["nmap_header_state"], style="green")
        table.add_column(LANG["nmap_header_service"], style="magenta")
        table.add_column(LANG["nmap_header_version"], style="yellow")
        port_lines = [line for line in output.split('\n') if "/tcp" in line and "open" in line]
        if not port_lines:
             table.add_row(LANG["nmap_no_ports_found"], "", "", "")
        else:
            for line in port_lines:
                parts = line.split()
                port, state, service = parts[0], parts[1], parts[2]
                version = " ".join(parts[3:])
                table.add_row(port, state, service, version)
        
        os_info = LANG["nmap_os_info_not_found"]
        for line in output.split('\n'):
            if line.strip().startswith("OS details:"):
                os_info = line.strip().replace("OS details: ", "")
                break
            elif line.strip().startswith("Running:"):
                 os_info = line.strip().replace("Running: ", "")
        
        return [table, Panel(os_info, border_style="cyan", title=LANG["nmap_os_title"])]
    except FileNotFoundError:
        console.print("\n[bold red]ERROR: 'nmap' command not found. Please install it (sudo apt install nmap).[/bold red]")
    except subprocess.TimeoutExpired:
        console.print(f"\n[bold red]ERROR: Scan timed out for {target}.[/bold red]")
    return None

def run_traceroute(target, LANG):
    output = run_command(["traceroute", target], "Traceroute", target)
    if output:
        return Panel(output, border_style="cyan", title=f"Traceroute to {target}")
    return None

def run_geolocation(target, LANG):
    try:
        ip_address = socket.gethostbyname(target)
        output = run_command(["curl", "-s", f"ipinfo.io/{ip_address}"], "GeoIP", ip_address)
        if output:
            return Panel(output, border_style="cyan", title=f"GeoIP Data for {target} ({ip_address})")
    except socket.gaierror:
        console.print(f"\n[bold red]ERROR: Could not resolve IP for '{target}'.[/bold red]")
    return None

def run_ssl_scan(target, LANG):
    command = ["openssl", "s_client", "-connect", f"{target}:443", "-servername", target]
    output = run_command(command, "SSL Scan", target)
    if output:
        table = Table(title=f"SSL Certificate Analysis for {target}", style="blue")
        table.add_column("Attribute", style="cyan")
        table.add_column("Details", style="green")
        subject = next((line.split(':', 1)[1].strip() for line in output.split('\n') if 'Subject:' in line), "N/A")
        issuer = next((line.split(':', 1)[1].strip() for line in output.split('\n') if 'Issuer:' in line), "N/A")
        not_before = next((line.split('=', 1)[1].strip() for line in output.split('\n') if 'Not Before' in line), "N/A")
        not_after = next((line.split('=', 1)[1].strip() for line in output.split('\n') if 'Not After' in line), "N/A")
        table.add_row("Subject", subject)
        table.add_row("Issuer", issuer)
        table.add_row("Valid From", not_before)
        table.add_row("Valid Until", not_after)
        return table
    return None

def run_http_headers(target, LANG):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["curl", "-I", "-L", url], "HTTP Headers", url)
    if output:
        return Panel(output, border_style="cyan", title=f"HTTP Headers for {url}")
    return None

def run_cookies_analyzer(target, LANG):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["curl", "-s", "-I", "-L", "-c", "/dev/null", url], "Cookie Analysis", url)
    if output:
        cookies = [line for line in output.split('\n') if line.lower().startswith('set-cookie:')]
        if cookies:
            return Panel("\n".join(cookies), border_style="cyan", title=f"Cookies from {url}")
        else:
            return Panel(f"Server did not set any cookies for {url}", border_style="yellow")
    return None

def run_tech_detection(target, LANG):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["whatweb", "--no-errors", url], "Tech Detection", url)
    if output:
        return Panel(output, border_style="cyan", title=f"Technology Stack & CMS for {url}")
    return None

def run_content_discovery(target, LANG):
    console.print(f"\n[yellow]>>> Searching for content on [bold green]{target}[/bold green] with [bold cyan]ffuf[/bold cyan]...[/yellow]")
    url = 'https://' + target.rstrip('/') if not target.startswith(('http://', 'https://')) else target.rstrip('/')
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    if not os.path.exists(wordlist):
        console.print(f"[bold red]ERROR: Wordlist not found at {wordlist}[/bold red]")
        return None
    command = ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ", "-c", "-t", "50", "-fs", "0"]
    try:
        console.print("[cyan]Starting ffuf... This may take a while. Press Ctrl+C to stop.[/cyan]")
        result = subprocess.run(command, capture_output=True, text=True)
        return Panel(result.stdout.strip(), border_style="cyan", title=f"FFUF results for {target}")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan stopped by user.[/bold yellow]")
    return None

def run_subdomain_enum(target, LANG):
    
    console.print(f"\n[yellow]>>> Searching for subdomains on [bold green]{target}[/bold green] with [bold cyan]Nmap[/bold cyan]...[/yellow]")
    console.print("[cyan]This may take several minutes...[/cyan]")
    
    command = ["nmap", "--script", "dns-brute", target]
    output = run_command(command, "Nmap DNS Brute", target)
    
    if output:
        
        subdomains = []
        for line in output.split('\n'):
            
            if target in line and (line.strip().startswith('|   ') or line.strip().startswith('|_  ')):
                
                subdomain = line.strip().split()[1]
                subdomains.append(subdomain)
        
        if subdomains:
            clean_output = "\n".join(subdomains)
            return Panel(clean_output, border_style="cyan", title=f"Subdomains for {target} (found with Nmap)")
        else:
            return Panel(f"No subdomains found for {target}", border_style="yellow")
    return None

def run_txt_records(target, LANG):
    output = run_command(["dig", target, "TXT", "+short"], "TXT Records", target)
    if output:
        return Panel(output, border_style="cyan", title=f"TXT Records for {target}")
    return None

def run_robots_analyzer(target, LANG):
    url = 'https://' + target.rstrip('/') + '/robots.txt'
    output = run_command(["curl", "-s", "-L", url], "Robots.txt", url)
    if output:
        return Panel(output, border_style="cyan", title=f"robots.txt for {target}")
    else:
        return Panel(f"No robots.txt file found for {target}", border_style="yellow")
    return None

def run_virustotal_check(target, LANG):
    url = f"https://www.virustotal.com/gui/domain/{target}"
    return Panel(f"Report for [bold green]{target}[/bold green] is available at:\n\n[link={url}]{url}[/link]", 
                border_style="cyan", title="VirusTotal Report Link")

def run_subdomain_takeover(target, LANG, FINGERPRINTS):
    console.print(f"\n[yellow]>>> Checking for Subdomain Takeover on [bold green]{target}[/bold green]...[/yellow]")
    subdomains_output = run_command(["subfinder", "-d", target, "-silent"], "Subdomain Enum", target)
    if not subdomains_output:
        return Panel(f"Could not find any subdomains for {target}.", border_style="yellow")

    subdomains = subdomains_output.split('\n')
    vulnerable_subs = []
    with console.status(f"[bold green]Checking {len(subdomains)} subdomains...[/bold green]") as status:
        for sub in subdomains:
            status.update(f"{LANG['sub_takeover_checking']} [cyan]{sub}[/cyan]...")
            try:
                answers = dns.resolver.resolve(sub, 'CNAME')
                if not answers:
                    continue
                response = requests.get(f"http://{sub}", timeout=5)
                for service, fingerprint in FINGERPRINTS.items():
                    if fingerprint in response.text:
                        vulnerable_subs.append((sub, service))
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, requests.RequestException):
                continue
    table = Table(title=f"Subdomain Takeover Scan for {target}", style="blue")
    table.add_column(LANG['sub_takeover_header_subdomain'], style="cyan")
    table.add_column(LANG['sub_takeover_header_service'], style="magenta")
    if not vulnerable_subs:
        table.add_row(LANG['sub_takeover_no_vuln'], "")
    else:
        for sub, service in vulnerable_subs:
            table.add_row(sub, service)
    return table
