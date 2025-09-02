#!/usr/bin/env python3
import os
import subprocess
import socket
from time import sleep
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import questionary
from questionary import Style
import dns.resolver
import requests

RU = {
    "exit_message": "Завершение работы.",
    "welcome_message": "Выберите язык / Select Language",
    "menu_title": "Выберите инструмент для использования",
    "recon_separator": "== Разведка и Сбор Информации ==",
    "web_separator": "== Анализ Веб-приложений ==",
    "vuln_separator": "== Поиск уязвимостей ==",
    "other_separator": "== Прочее ==",
    "exit_option": "Выход",
    "help_option": "Справка",
    "target_prompt": "Введите цель (домен) для",
    "target_not_entered": "Цель не была введена. Возврат в меню...",
    "continue_prompt": "\nНажмите Enter, чтобы вернуться в меню...",
    "operation_cancelled": "Операция отменена. Возврат в меню...",
    "help_title": "Справка по инструментам 4Blue",
    "command_header": "Команда",
    "description_header": "Описание",
    "nmap_start_scan": ">>> Запускаю углубленное сканирование на [bold green]{target}[/bold green] с помощью [bold cyan]Nmap[/bold cyan]...",
    "nmap_wait_message": "[cyan]Определяю порты, версии и ОС. Это может занять до минуты...[/cyan]",
    "nmap_error_title": "Ошибка Nmap",
    "nmap_report_title": "Отчет о сканировании Nmap для {target}",
    "nmap_header_port": "Порт",
    "nmap_header_state": "Состояние",
    "nmap_header_service": "Сервис",
    "nmap_header_version": "Версия",
    "nmap_no_ports_found": "Открытых портов не найдено",
    "nmap_os_info_not_found": "Информация об ОС не найдена.",
    "nmap_os_title": "Предполагаемая ОС",
    "sub_takeover_header_subdomain": "Субдомен",
    "sub_takeover_header_service": "Уязвимый сервис",
    "sub_takeover_no_vuln": "Уязвимых субдоменов не найдено.",
    "sub_takeover_checking": "Проверяю субдомен",
    "help_data": {
        "WHOIS Lookup": "Получает регистрационные данные домена.",
        "DNS Records": "Показывает основные DNS-записи домена.",
        "Port Scan (Nmap)": "Сканирует популярные порты, их версии и ОС.",
        "Traceroute": "Отслеживает сетевой маршрут до сервера цели.",
        "GeoIP Location": "Определяет физическое местоположение сервера.",
        "SSL/TLS Scan": "Анализирует SSL-сертификат сайта.",
        "Subdomain Enumeration": "Находит субдомены для указанного домена.",
        "TXT Records": "Получает TXT-записи DNS, часто используемые для верификации.",
        "HTTP Headers": "Показывает HTTP-заголовки, которые возвращает сервер.",
        "Cookies Analyzer": "Анализирует cookie-файлы, которые сайт пытается установить.",
        "Tech & CMS Detection": "Определяет технологии и CMS, на которых работает сайт.",
        "Robots.txt Analyzer": "Анализирует файл robots.txt на предмет скрытых ресурсов.",
        "VirusTotal Scan": "Генерирует ссылку на отчет о репутации домена в VirusTotal.",
        "Subdomain Takeover": "Проверяет, уязвимы ли субдомены для захвата (Python-версия).",
        "Content Discovery": "Ищет скрытые файлы и директории на сервере."
    }
}
EN = {
    "exit_message": "Exiting program.",
    "welcome_message": "Select Language / Выберите язык",
    "menu_title": "Select a tool to use",
    "recon_separator": "== Reconnaissance & Information Gathering ==",
    "web_separator": "== Web Application Analysis ==",
    "vuln_separator": "== Vulnerability Scanning ==",
    "other_separator": "== Other ==",
    "exit_option": "Exit",
    "help_option": "Help",
    "target_prompt": "Enter target (domain) for",
    "target_not_entered": "Target was not entered. Returning to menu...",
    "continue_prompt": "\nPress Enter to return to the menu...",
    "operation_cancelled": "Operation cancelled. Returning to menu...",
    "help_title": "4Blue Tools Help",
    "command_header": "Command",
    "description_header": "Description",
    "nmap_start_scan": ">>> Running advanced scan on [bold green]{target}[/bold green] with [bold cyan]Nmap[/bold cyan]...",
    "nmap_wait_message": "[cyan]Detecting ports, versions, and OS. This may take up to a minute...[/cyan]",
    "nmap_error_title": "Nmap Error",
    "nmap_report_title": "Nmap Scan Report for {target}",
    "nmap_header_port": "Port",
    "nmap_header_state": "State",
    "nmap_header_service": "Service",
    "nmap_header_version": "Version",
    "nmap_no_ports_found": "No open ports found",
    "nmap_os_info_not_found": "OS information not found.",
    "nmap_os_title": "Operating System Guess",
    "sub_takeover_header_subdomain": "Subdomain",
    "sub_takeover_header_service": "Vulnerable Service",
    "sub_takeover_no_vuln": "No vulnerable subdomains found.",
    "sub_takeover_checking": "Checking subdomain",
    "help_data": {
        "WHOIS Lookup": "Retrieves domain registration data.",
        "DNS Records": "Shows domain's primary DNS records.",
        "Port Scan (Nmap)": "Scans popular ports, their versions, and the OS.",
        "Traceroute": "Traces the network route to the target's server.",
        "GeoIP Location": "Determines the physical location of the server.",
        "SSL/TLS Scan": "Analyzes the site's SSL certificate.",
        "Subdomain Enumeration": "Discovers subdomains for the target domain.",
        "TXT Records": "Fetches DNS TXT records, often used for verification.",
        "HTTP Headers": "Displays the HTTP headers returned by the server.",
        "Cookies Analyzer": "Analyzes the cookies that the site attempts to set.",
        "Tech & CMS Detection": "Identifies the technologies and CMS the site is running on.",
        "Robots.txt Analyzer": "Analyzes the robots.txt file for disallowed resources.",
        "VirusTotal Scan": "Generates a link to the domain's reputation report on VirusTotal.",
        "Subdomain Takeover": "Tests if any subdomains are vulnerable to takeover (Python version).",
        "Content Discovery": "Searches for hidden files and directories on the server."
    }
}

console = Console()
LANG = {}

LOGO = """
                                 ██╗  ██╗██████╗ ██╗     ██╗   ██╗███████╗
                                 ██║  ██║██╔══██╗██║     ██║   ██║██╔════╝
                                 ███████║██████╔╝██║     ██║   ██║█████╗  
                                 ╚════██║██╔══██╗██║     ██║   ██║██╔══╝  
                                      ██║██████╔╝███████╗╚██████╔╝███████╗
                                      ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ 
        
                               By: Vahe24 | Version: 0.1 | 4Blue for self use
"""

FINGERPRINTS = {
    "GitHub": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "AWS/S3": "The specified bucket does not exist",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Squarespace": "You've been directed to a Squarespace parking page.",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address."
}

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

def show_help():
    table = Table(title=LANG["help_title"], style="blue", show_header=True, header_style="bold magenta")
    table.add_column(LANG["command_header"], style="cyan", width=25)
    table.add_column(LANG["description_header"], style="green")
    for command, desc in LANG["help_data"].items():
        table.add_row(command, desc)
    console.print(table)

def run_whois(target):
    output = run_command(["whois", target], "WHOIS", target)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"WHOIS Report for {target}"))

def run_dns_records(target):
    output = run_command(["dig", target, "ANY"], "DNS Records", target)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"DNS Records for {target}"))

def run_port_scan(target):
    console.print(LANG["nmap_start_scan"].format(target=target))
    console.print(LANG["nmap_wait_message"])
    command = ["sudo", "nmap", "-F", "-sV", "-O", "--open", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()
        if not output and result.stderr:
             console.print(Panel(result.stderr.strip(), border_style="red", title=LANG["nmap_error_title"]))
             return
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
        console.print(table)
        os_info = LANG["nmap_os_info_not_found"]
        for line in output.split('\n'):
            if line.strip().startswith("OS details:"):
                os_info = line.strip().replace("OS details: ", "")
                break
            elif line.strip().startswith("Running:"):
                 os_info = line.strip().replace("Running: ", "")
        console.print(Panel(os_info, border_style="cyan", title=LANG["nmap_os_title"]))
    except FileNotFoundError:
        console.print("\n[bold red]ERROR: 'nmap' command not found. Please install it (sudo apt install nmap).[/bold red]")
    except subprocess.TimeoutExpired:
        console.print(f"\n[bold red]ERROR: Scan timed out for {target}.[/bold red]")

def run_traceroute(target):
    output = run_command(["traceroute", target], "Traceroute", target)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"Traceroute to {target}"))

def run_geolocation(target):
    try:
        ip_address = socket.gethostbyname(target)
        output = run_command(["curl", "-s", f"ipinfo.io/{ip_address}"], "GeoIP", ip_address)
        if output:
            console.print(Panel(output, border_style="cyan", title=f"GeoIP Data for {target} ({ip_address})"))
    except socket.gaierror:
        console.print(f"\n[bold red]ERROR: Could not resolve IP for '{target}'.[/bold red]")

def run_ssl_scan(target):
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
        console.print(table)

def run_http_headers(target):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["curl", "-I", "-L", url], "HTTP Headers", url)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"HTTP Headers for {url}"))

def run_cookies_analyzer(target):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["curl", "-s", "-I", "-L", "-c", "/dev/null", url], "Cookie Analysis", url)
    if output:
        cookies = [line for line in output.split('\n') if line.lower().startswith('set-cookie:')]
        if cookies:
            console.print(Panel("\n".join(cookies), border_style="cyan", title=f"Cookies from {url}"))
        else:
            console.print(f"[cyan]Server did not set any cookies for {url}[/cyan]")

def run_tech_detection(target):
    url = 'https://' + target if not target.startswith(('http://', 'https://')) else target
    output = run_command(["whatweb", "--no-errors", url], "Tech Detection", url)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"Technology Stack & CMS for {url}"))

def run_content_discovery(target):
    console.print(f"\n[yellow]>>> Searching for content on [bold green]{target}[/bold green] with [bold cyan]ffuf[/bold cyan]...[/yellow]")
    url = 'https://' + target.rstrip('/') if not target.startswith(('http://', 'https://')) else target.rstrip('/')
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    if not os.path.exists(wordlist):
        console.print(f"[bold red]ERROR: Wordlist not found at {wordlist}[/bold red]")
        return
    command = ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ", "-c", "-t", "50", "-fs", "0"]
    try:
        console.print("[cyan]Starting ffuf... This may take a while. Press Ctrl+C to stop.[/cyan]")
        subprocess.run(command)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan stopped by user.[/bold yellow]")

def run_subdomain_enum(target):
    output = run_command(["subfinder", "-d", target, "-silent"], "Subdomain Enum", target)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"Subdomains for {target}"))

def run_txt_records(target):
    output = run_command(["dig", target, "TXT", "+short"], "TXT Records", target)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"TXT Records for {target}"))

def run_robots_analyzer(target):
    url = 'https://' + target.rstrip('/') + '/robots.txt'
    output = run_command(["curl", "-s", "-L", url], "Robots.txt", url)
    if output:
        console.print(Panel(output, border_style="cyan", title=f"robots.txt for {target}"))
    else:
        console.print(f"[yellow]No robots.txt file found for {target}[/yellow]")

def run_virustotal_check(target):
    url = f"https://www.virustotal.com/gui/domain/{target}"
    console.print(Panel(f"Report for [bold green]{target}[/bold green] is available at:\n\n[link={url}]{url}[/link]", 
                border_style="cyan", title="VirusTotal Report Link"))

def run_subdomain_takeover(target):
    console.print(f"\n[yellow]>>> Checking for Subdomain Takeover on [bold green]{target}[/bold green]...[/yellow]")
    subdomains_output = run_command(["subfinder", "-d", target, "-silent"], "Subdomain Enum", target)
    if not subdomains_output:
        console.print(f"[yellow]Could not find any subdomains for {target}.[/yellow]")
        return
    subdomains = subdomains_output.split('\n')
    vulnerable_subs = []
    with console.status(f"[bold green]Checking {len(subdomains)} subdomains...[/bold green]") as status:
        for sub in subdomains:
            status.update(f"{LANG['sub_takeover_checking']} [cyan]{sub}[/cyan]...")
            try:
                answers = dns.resolver.resolve(sub, 'CNAME')
                if not answers:
                    continue
                cname = answers[0].to_text()
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
    console.print(table)


def main():
    global LANG
    try:
        lang_choice = questionary.select(RU["welcome_message"], choices=['Русский', 'English']).ask()
        LANG = RU if lang_choice == 'Русский' else EN
    except (KeyboardInterrupt, TypeError):
        console.print(f"\n[bold red]{RU.get('exit_message', 'Exiting program.')}[/bold red]")
        return

    actions = {
        "WHOIS Lookup": run_whois, "DNS Records": run_dns_records, "Port Scan (Nmap)": run_port_scan,
        "Traceroute": run_traceroute, "GeoIP Location": run_geolocation, "SSL/TLS Scan": run_ssl_scan,
        "Subdomain Enumeration": run_subdomain_enum, "TXT Records": run_txt_records, "HTTP Headers": run_http_headers,
        "Cookies Analyzer": run_cookies_analyzer, "Tech & CMS Detection": run_tech_detection,
        "Robots.txt Analyzer": run_robots_analyzer, "VirusTotal Scan": run_virustotal_check,
        "Subdomain Takeover": run_subdomain_takeover, "Content Discovery": run_content_discovery
    }
    
    custom_style = Style([
        ('separator', 'bold fg:#00bfff'),
        ('questionmark', 'fg:#00bfff bold'),
        ('selected', 'fg:black bg:#00bfff'),
        ('pointer', 'fg:#00bfff bold'),
        ('instruction', 'fg:#858585'),
        ('answer', 'fg:#00bfff bold'),
        ('question', 'bold'),
    ])

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(Panel(LOGO, style="bold blue", border_style="blue", highlight=True))
        try:
            choices = [
                questionary.Separator(LANG["recon_separator"]), *list(actions.keys())[0:8],
                questionary.Separator(LANG["web_separator"]), *list(actions.keys())[8:12],
                questionary.Separator(LANG["vuln_separator"]), *list(actions.keys())[12:15],
                questionary.Separator(LANG["other_separator"]),
                {"name": LANG["help_option"], "style": "fg:green"},
                {"name": LANG["exit_option"], "style": "fg:red"},
            ]
            choice = questionary.select(LANG["menu_title"], choices=choices, style=custom_style, use_indicator=True).ask()
        except KeyboardInterrupt:
            choice = LANG["exit_option"]

        if choice == LANG["exit_option"] or not choice:
            console.print(f'\n[bold red]{LANG.get("exit_message", "Exiting program.")}[/bold red]')
            break
        elif choice == LANG["help_option"]:
            show_help()
            input(LANG["continue_prompt"])
        elif choice in actions:
            try:
                target = questionary.text(f'{LANG["target_prompt"]} [{choice}]:', style=custom_style).ask()
                if target:
                    actions[choice](target)
                    input(LANG["continue_prompt"])
                else:
                    console.print(f'\n[bold red]{LANG["target_not_entered"]}[/bold red]')
                    sleep(2)
            except KeyboardInterrupt:
                console.print(f"\n[bold yellow]{LANG['operation_cancelled']}[/bold yellow]")
                sleep(2)

if __name__ == "__main__":
    main()
