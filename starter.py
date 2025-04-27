import sys
import os
import platform
import subprocess
import random
import time
import colorama
import selenium
from colorama import Fore, Style
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
    # Çakışan parametreler kontrolü
    if setting.FAST_SCAN.lower() == "on" and setting.FULL_SCAN.lower() == "on":
        print_error_and_exit("FAST ve FULL parametreleri aynı anda kullanılamaz.")

    if setting.FULL_SCAN.lower() == "on":
        for scanner in [setting.SQLMAP, setting.WPSCAN, setting.NIKTO, setting.ZAPROXY, setting.METASPLOIT]:
            if scanner.lower() == "on":
                print_error_and_exit("FULL ile diğer tarama modları (SQLMAP, WPSCAN, NIKTO, vb.) aynı anda kullanılamaz.")

def print_error_and_exit(message):
    print(f"{Fore.RED}HATA: {message}{Style.RESET_ALL}")
    input(f"{Fore.RED}HATA nedeniyle işlem sonlandırıldı. Programı kapatıp tekrar açınız.{Style.RESET_ALL}")
    sys.exit(1)

# Tarayıcı başlatma
def start_browser():
    options = webdriver.ChromeOptions()
    
    # User-Agent başlığını al
    user_agent = useragent.get_random_useragent()
    options.add_argument(f"user-agent={user_agent}")  # Rastgele seçilen User-Agent'ı ekle
    
    options.add_argument("--headless")  # Tarayıcıyı görünmeden çalıştırmak için
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver

# Dork araması için motorlardan sonuç alma
def dork_search(driver, query, engines=['google', 'bing'], num_results=10):
    print(f"[+] {query} için dork araması başlatılıyor...")
    results = []

    for engine in engines:
        if engine == 'google':
            # Google Dork Tarama
            search_url = f"https://www.google.com/search?q={query}"
            driver.get(search_url)
            time.sleep(3)
            results.extend([a.get_attribute('href') for a in driver.find_elements(By.CSS_SELECTOR, 'a') if a.get_attribute('href')])
        elif engine == 'bing':
            # Bing Dork Tarama
            search_url = f"https://www.bing.com/search?q={query}"
            driver.get(search_url)
            time.sleep(3)
            results.extend([a.get_attribute('href') for a in driver.find_elements(By.CSS_SELECTOR, 'a') if a.get_attribute('href')])

    return results[:num_results]

# Captcha çözme işlemi (manuel)
def solve_captcha(driver):
    print(f"{Fore.YELLOW}[!] Captcha tespit edildi, lütfen manuel olarak çözün.{Style.RESET_ALL}")
    input(f"{Fore.YELLOW}Captcha'yı çözüp Enter'a basın: {Style.RESET_ALL}")

def save_results_to_file(results, filename="scan_results/dork_result.txt"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)  # Klasörleri oluştur
    with open(filename, 'a', encoding="utf-8") as f:  # 'a' parametresiyle dosyaya ekleme yapılır
        for result in results:
            f.write(f"{result}\n")
    print(f"{Fore.GREEN}[+] Sonuçlar {filename} dosyasına kaydedildi.{Style.RESET_ALL}")

# Çalıştırıcı Fonksiyonlar
def run_dork_scan():
    print(f"{Fore.CYAN}[+] Dork taraması başlatılıyor...{Style.RESET_ALL}")
    
    # Dork Sorgusu Seçimi
    if setting.DORK:
        dork_query = setting.DORK
        targets = dork_search(driver, dork_query, engines=['google', 'bing'], num_results=20)
    elif setting.DORK_INPUT:
        with open(setting.DORK_INPUT, "r", encoding="utf-8") as f:
            dork_queries = f.read().splitlines()
        
        targets = []
        for query in dork_queries:
            found = dork_search(driver, query, engines=['google', 'bing'], num_results=10)
            targets.extend(found)
    else:
        print(f"{Fore.RED}[!] Dork veya dork-input verilmemiş.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}[+] Bulunan hedefler ({len(targets)}):{Style.RESET_ALL}")
    for url in targets:
        print(f"   -> {url}")
        driver.get(url)
        time.sleep(3)

        # Eğer bir captcha varsa, çözülmesini iste
        if "captcha" in driver.page_source.lower():
            solve_captcha(driver)

    # Sonuçları dosyaya kaydet
    save_results_to_file(targets)

    driver.quit()
    # Tarayıcı başlatma
    driver = start_browser()

def run_sqlmap():
    print(f"{Fore.CYAN}[+] SQLMAP taraması başlatılıyor...{Style.RESET_ALL}")

    level = int(setting.LEVEL)
    
    # Level'e göre Risk ayarla
    if level <= 2:
        risk = 1
    elif level <= 4:
        risk = 2
    else:
        risk = 3

    # Derinlik ekleyelim, LEVEL'e göre
    if level == 1:
        depth = 1
    elif level == 2:
        depth = 2
    elif level == 3:
        depth = 3
    elif level == 4:
        depth = 4
    else:
        depth = 5

    command = [
        "sqlmap",
        "-u", setting.TARGET,
        "--level", str(level),
        "--risk", str(risk),
        "--depth", str(depth),
        "--batch"
    ]

    subprocess.run(command)

def run_wpscan():
    print(f"{Fore.CYAN}[+] WPSCAN taraması başlatılıyor...{Style.RESET_ALL}")

    command = [
        "wpscan",
        "--url", setting.TARGET,
        "--disable-tls-checks",
        "--random-user-agent"
    ]

    subprocess.run(command)

def run_nikto():
    print(f"{Fore.CYAN}[+] NIKTO taraması başlatılıyor...{Style.RESET_ALL}")

    command = [
        "nikto",
        "-h", setting.TARGET
    ]

    subprocess.run(command)

def run_zaproxy():
    print(f"{Fore.CYAN}[+] OWASP ZAP taraması başlatılıyor...{Style.RESET_ALL}")

    command = [
        "zap-cli",
        "quick-scan",
        "--self-contained",
        setting.TARGET
    ]

    subprocess.run(command)

def run_metasploit():
    print(f"{Fore.CYAN}[+] METASPLOIT taraması başlatılıyor...{Style.RESET_ALL}")

    # Burada örnek msfconsole komutu basit bırakıldı.
    command = [
        "msfconsole",
        "-q", 
        "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {setting.TARGET}; run; exit"
    ]

    subprocess.run(command)

def run_full_scan():
    print(f"{Fore.CYAN}[+] FULL tarama başlatılıyor...{Style.RESET_ALL}")
    run_sqlmap()
    run_wpscan()
    run_nikto()
    run_zaproxy()
    run_metasploit()

# Ana işlem akışı
def işlem_sıralama():
    if setting.DORK or setting.DORK_INPUT:
        run_dork_scan()
    else:
        if setting.FULL_SCAN.lower() == "on":
            run_sqlmap()
            run_wpscan()
            run_nikto()
            run_zaproxy()
            run_metasploit()
        else:
            if setting.SQLMAP.lower() == "on":
                run_sqlmap()
            if setting.WPSCAN.lower() == "on":
                run_wpscan()
            if setting.NIKTO.lower() == "on":
                run_nikto()
            if setting.ZAPROXY.lower() == "on":
                run_zaproxy()
            if setting.METASPLOIT.lower() == "on":
                run_metasploit()

if __name__ == "__main__":

    işlem_sıralama()
