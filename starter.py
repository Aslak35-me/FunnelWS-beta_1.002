import sys
import os
import platform
import subprocess
import random
import time
import colorama
import selenium
import threading
from colorama import init, Fore, Style
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# colorama başlat
init(autoreset=True)

# config klasörünü sys.path'e ekle
sys.path.append(os.path.join(os.path.dirname(__file__), 'config'))

import config.setting as setting
import useragent
from useragent import get_random_useragent

# Global driver değişkeni
driver = None

def clear_console():
    current_os = platform.system()
    os.system('cls' if current_os == "Windows" else 'clear')

def banner():
    print(r"""
+----------------------------------------------------+
|                                                    |
|                                                    |
|   _____                       ___        ______    |
|  |  ___|   _ ____  ____   ___| \ \      / / ___|   |
|  | |_ | | | | __ \| __ \ / _ \ |\ \ /\ / /\___ \   |
|  |  _|| |_| | | | | | | |  __/ | \ V  V /  ___) |  |
|  |_|   \____|_| |_|_| |_|\___|_|  \_/\_/  |____/   |
|                                                    |
|                                                    |
+----------------------------------------------------+
    """)
    print("[*] FunnelWS Web Vulnerability Scanner")
    version()
    print("=" * 55)
    print("[*] Starter başlatıldı.")
    print("=" * 55)

def version():
    print("[*] FunnelWS Version BETA_1.002")

def check_settings():
    checks = [
        ("FULL_SCAN", setting.FULL_SCAN),
        ("FAST_SCAN", setting.FAST_SCAN),
        ("SQLMAP", setting.SQLMAP),
        ("WPSCAN", setting.WPSCAN),
        ("NIKTO", setting.NIKTO),
        ("ZAPROXY", setting.ZAPROXY),
        ("METASPLOIT", setting.METASPLOIT)
        ("WHOİS", setting.WHOİS)
    ]

    for name, value in checks:
        status = value.lower()
        if status == "on":
            print(f"[*] {name} aktif.")
        elif status == "off":
            print(f"[*] {name} pasif.")
        else:
            print(f"{Fore.YELLOW}[!] {name} bilinmeyen durumda: {value}{Style.RESET_ALL}")

    print("[*] Diğer ayarlar setting.py'den alındı.")

def check_conflicts():
    if setting.FAST_SCAN.lower() == "on" and setting.FULL_SCAN.lower() == "on":
        print_error_and_exit("FAST ve FULL parametreleri aynı anda kullanılamaz.")

    if setting.FULL_SCAN.lower() == "on":
        for scanner in [setting.SQLMAP, setting.WPSCAN, setting.NIKTO, setting.ZAPROXY, setting.METASPLOIT]:
            if scanner.lower() == "on":
                print_error_and_exit("FULL ile diğer tarama modları aynı anda kullanılamaz.")

def print_error_and_exit(message):
    print(f"{Fore.RED}HATA: {message}{Style.RESET_ALL}")
    input(f"{Fore.RED}Program sonlandırıldı. Enter'a basarak çıkabilirsiniz.{Style.RESET_ALL}")
    sys.exit(1)

def start_browser():
    options = webdriver.ChromeOptions()
    user_agent = get_random_useragent()
    options.add_argument(f"user-agent={user_agent}")
    options.add_argument("--headless")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver

def dork_search(driver, query, engines=['google', 'bing'], num_results=10):
    print(f"[+] {query} için dork araması başlatılıyor...")
    results = []

    for engine in engines:
        if engine == 'google':
            driver.get(f"https://www.google.com/search?q={query}")
        elif engine == 'bing':
            driver.get(f"https://www.bing.com/search?q={query}")
        time.sleep(3)
        results.extend([a.get_attribute('href') for a in driver.find_elements(By.CSS_SELECTOR, 'a') if a.get_attribute('href')])

    return results[:num_results]

def solve_captcha(driver):
    print(f"{Fore.YELLOW}[!] Captcha tespit edildi. Manuel çözüm bekleniyor.{Style.RESET_ALL}")
    input(f"{Fore.YELLOW}Captcha'yı çözün ve Enter'a basın.{Style.RESET_ALL}")

def save_results_to_file(results, filename="scan_results/dork_result.txt"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'a', encoding="utf-8") as f:
        for result in results:
            f.write(f"{result}\n")
    print(f"{Fore.GREEN}[+] Sonuçlar {filename} dosyasına kaydedildi.{Style.RESET_ALL}")

def time_tracker(task_name, duration_in_seconds):
    start_time = time.time()
    end_time = start_time + duration_in_seconds
    while time.time() < end_time:
        remaining_time = int(end_time - time.time())
        minutes, seconds = divmod(remaining_time, 60)
        print(f"[ / ] {task_name}: Kalan süre: {minutes:02}:{seconds:02}", end="\r")
        time.sleep(1)
    print(f"[🆗] {task_name}: Süresi bitti!")

# --- Tarama Fonksiyonları ---

def run_dork_scan():
    print(f"{Fore.CYAN}[+] Dork taraması başlatılıyor...{Style.RESET_ALL}")
    global driver
    if not driver:
        driver = start_browser()

    targets = []

    if setting.DORK:
        targets = dork_search(driver, setting.DORK, num_results=20)
    elif setting.DORK_INPUT:
        with open(setting.DORK_INPUT, "r", encoding="utf-8") as f:
            dork_queries = f.read().splitlines()
        for query in dork_queries:
            found = dork_search(driver, query, num_results=10)
            targets.extend(found)
    else:
        print(f"{Fore.RED}[!] Dork veya dork-input verilmemiş.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}[+] Bulunan hedefler ({len(targets)}):{Style.RESET_ALL}")
    for url in targets:
        print(f"   -> {url}")
        driver.get(url)
        time.sleep(2)
        if "captcha" in driver.page_source.lower():
            solve_captcha(driver)

    save_results_to_file(targets)

def run_panelfinder():
    print(f"{Fore.CYAN}[+] Panel bulucu çalıştırılıyor...{Style.RESET_ALL}")
    panels = ["/admin", "/panel", "/admin/login.php", "/cpanel", "/login", "/administrator"]
    for panel in panels:
        full_url = f"{setting.TARGET}{panel}"
        print(f"Denetlenen: {full_url}")

def run_sqlmap():
    print(f"{Fore.CYAN}[+] SQLMAP taraması başlatılıyor...{Style.RESET_ALL}")
    level = int(setting.LEVEL)
    risk = 1 if level <= 2 else (2 if level <= 4 else 3)
    depth = level if level <= 5 else 5
    command = ["sqlmap", "-u", setting.TARGET, "--level", str(level), "--risk", str(risk), "--depth", str(depth), "--batch"]

    if setting.RANDOM_AGENT.lower() == "on":
        user_agent = get_random_useragent()
        command += ["--user-agent", user_agent]

    subprocess.run(command)

def run_wpscan():
    print(f"{Fore.CYAN}[+] WPSCAN taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["wpscan", "--url", setting.TARGET, "--disable-tls-checks"]
    if setting.RANDOM_AGENT.lower() == "on":
        user_agent = get_random_useragent()
        command += ["--user-agent", user_agent]
    subprocess.run(command)

def run_nikto():
    print(f"{Fore.CYAN}[+] NIKTO taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["nikto", "-h", setting.TARGET]
    if setting.RANDOM_AGENT.lower() == "on":
        user_agent = get_random_useragent()
        command += ["-useragent", user_agent]
    subprocess.run(command)

def run_zaproxy():
    print(f"{Fore.CYAN}[+] OWASP ZAP taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["zap-cli", "quick-scan", "--self-contained", setting.TARGET]
    if setting.RANDOM_AGENT.lower() == "on":
        user_agent = get_random_useragent()
        command += ["--user-agent", user_agent]
    subprocess.run(command)

def run_metasploit():
    print(f"{Fore.CYAN}[+] METASPLOIT taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {setting.TARGET}; run; exit"]
    subprocess.run(command)

def run_whois():
    print(f"{Fore.CYAN}[+] WHOIS taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["whois", setting.TARGET]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"{Fore.GREEN}[+] WHOIS Sonuçları:\n{result.stdout}{Style.RESET_ALL}")
        os.makedirs("scan_results", exist_ok=True)
        with open("scan_results/whois_result.txt", "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"{Fore.GREEN}[+] WHOIS sonuçları 'scan_results/whois_result.txt' dosyasına kaydedildi.{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] WHOIS komutu çalıştırılırken hata oluştu: {e}{Style.RESET_ALL}")

def run_full_scan():
    print(f"{Fore.CYAN}[+] FULL tarama başlatılıyor...{Style.RESET_ALL}")
    threads = []
    scan_funcs = {
        "SQLMAP": run_sqlmap,
        "WPSCAN": run_wpscan,
        "NIKTO": run_nikto,
        "ZAPROXY": run_zaproxy,
        "METASPLOIT": run_metasploit
    }
    for name, func in scan_funcs.items():
        if getattr(setting, name).lower() == "on":
            thread = threading.Thread(target=func)
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

def işlem_sıralama():
    if setting.DORK.lower() == "on":
        time_tracker("Dork Tarama", 120)
        run_dork_scan()
    elif setting.FULL_SCAN.lower() == "on":
        time_tracker("FULL Tarama", 600)
        run_full_scan()
    else:
        scans = [
            (setting.SQLMAP, run_sqlmap, "SQLMAP"),
            (setting.WPSCAN, run_wpscan, "WPSCAN"),
            (setting.NIKTO, run_nikto, "NIKTO"),
            (setting.ZAPROXY, run_zaproxy, "ZAPROXY"),
            (setting.METASPLOIT, run_metasploit, "METASPLOIT")
            (setting.WHOİS, run_whois, "WHOİS")
        ]
        for active, func, name in scans:
            if active.lower() == "on":
                time_tracker(f"{name} Tarama", 60)
                func()

# Ana Çalıştırıcı
if __name__ == "__main__":
    clear_console()
    banner()
    check_settings()
    check_conflicts()
    driver = start_browser()
    işlem_sıralama()
    if driver:
        driver.quit()
