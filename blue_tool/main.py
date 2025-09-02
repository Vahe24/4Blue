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
from datetime import datetime

from .config import RU, EN, LOGO, FINGERPRINTS
from .scanners import (
    run_whois, run_dns_records, run_port_scan, run_traceroute, run_geolocation,
    run_ssl_scan, run_http_headers, run_cookies_analyzer, run_tech_detection,
    run_content_discovery, run_subdomain_enum, run_txt_records,
    run_robots_analyzer, run_virustotal_check, run_subdomain_takeover
)

console = Console()
LANG = {}

def save_result(target, tool_name, renderables, logo):
    if not isinstance(renderables, list):
        renderables = [renderables]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace('.', '_')
    
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    
    base_filename = f"{results_dir}/{sanitized_target}_{tool_name.replace(' ', '_')}_{timestamp}"
    
    report_console = Console(record=True, width=120)
    
    report_console.print(logo)
    
    if isinstance(renderables, list):
        for item in renderables:
            report_console.print(item)
    else:
        report_console.print(renderables)

    # Сохраняем только в HTML
    report_console.save_html(f"{base_filename}.html")

    console.print(f"\n[bold green]✓ {LANG['save_confirm']}:[/bold green]")
    console.print(f"  [cyan]{base_filename}.html[/cyan]")

def show_help():
    table = Table(title=LANG["help_title"], style="blue", show_header=True, header_style="bold magenta")
    table.add_column(LANG["command_header"], style="cyan", width=25)
    table.add_column(LANG["description_header"], style="green")
    for command, desc in LANG["help_data"].items():
        table.add_row(command, desc)
    console.print(table)

def main():
    global LANG
    try:
        lang_choice = questionary.select(RU["welcome_message"], choices=['Русский', 'English']).ask()
        if lang_choice is None:
            console.print(f"\n[bold red]{RU.get('exit_message', 'Exiting program.')}[/bold red]")
            return
        LANG = RU if lang_choice == 'Русский' else EN
    except KeyboardInterrupt:
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

    logo_panel = Panel(LOGO, style="bold blue", border_style="blue", highlight=True)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(logo_panel)
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
                    console.clear()
                    result = None
                    if choice == "Subdomain Takeover":
                        result = actions[choice](target, LANG, FINGERPRINTS)
                    else:
                        result = actions[choice](target, LANG)

                    if result:
                        if isinstance(result, list):
                            for item in result:
                                console.print(item)
                        else:
                            console.print(result)
                        
                        should_save = questionary.confirm(LANG['save_prompt'], default=False).ask()
                        if should_save:
                            save_result(target, choice, result, logo_panel)
                    
                    input(LANG["continue_prompt"])
                else:
                    console.print(f'\n[bold red]{LANG["target_not_entered"]}[/bold red]')
                    sleep(2)
            except KeyboardInterrupt:
                console.print(f"\n[bold yellow]{LANG['operation_cancelled']}[/bold yellow]")
                sleep(2)
