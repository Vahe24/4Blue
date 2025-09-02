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
    "save_prompt": "Хотите сохранить результат в файл?",
    "save_confirm": "Результаты сохранены в папку 'results'",
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
    "save_prompt": "Do you want to save the results to a file?",
    "save_confirm": "Results saved to 'results' folder",
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

LOGO = """
                                 ██╗  ██╗██████╗ ██╗     ██╗   ██╗███████╗
                                 ██║  ██║██╔══██╗██║     ██║   ██║██╔════╝
                                 ███████║██████╔╝██║     ██║   ██║█████╗  
                                 ╚════██║██╔══██╗██║     ██║   ██║██╔══╝  
                                      ██║██████╔╝███████╗╚██████╔╝███████╗
                                      ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ 
        
                               By: Vahe24 | Version: 1.1 | 4Blue for self use
"""

FINGERPRINTS = {
    "GitHub": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "AWS/S3": "The specified bucket does not exist",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Squarespace": "You've been directed to a Squarespace parking page.",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address."
}
