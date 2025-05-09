import sys
import os
import platform
import subprocess
import random
import time
import colorama
import selenium
import threading
import json
from colorama import init, Fore, Style

# colorama başlat
init(autoreset=True)

# config klasörünü sys.path'e ekle
sys.path.append(os.path.join(os.path.dirname(__file__), 'config'))

# setting.json dosyasını oku
with open(os.path.join(os.path.dirname(__file__), 'config', 'setting.json'), 'r', encoding='utf-8') as f:
    setting = json.load(f)

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

def check_setting():
    checks = [
        ("FULL_SCAN", setting.get("FULL_SCAN", "off")),
        ("FAST_SCAN", setting.get("FAST_SCAN", "off")),
        ("SQLMAP", setting.get("SQLMAP", "off")),
        ("WPSCAN", setting.get("WPSCAN", "off")),
        ("NIKTO", setting.get("NIKTO", "off")),
        ("ZAPROXY", setting.get("ZAPROXY", "off")),
        ("METASPLOIT", setting.get("METASPLOIT", "off")),
        ("WHOİS", setting.get("WHOİS", "off")),
        ("DORK_CHECK", setting.get("DORK_CHECK", "off")),
        ("DORK_FİLE_CHECK", setting.get("DORK_FİLE_CHECK", "off"))
    ]

    for name, value in checks:
        status = value.lower()
        if status == "on":
            print(f"[*] {name} aktif.")
        elif status == "off":
            print(f"[*] {name} pasif.")
        else:
            print(f"{Fore.YELLOW}[!] {name} bilinmeyen durumda: {value}{Style.RESET_ALL}")

    print("[*] Diğer ayarlar setting.json'dan alındı.")

def check_conflicts():
    if setting.get("FAST_SCAN", "off").lower() == "on" and setting.get("FULL_SCAN", "off").lower() == "on":
        print_error_and_exit("FAST ve FULL parametreleri aynı anda kullanılamaz.")

    if setting.get("FULL_SCAN", "off").lower() == "on":
        for scanner in [
            setting.get("SQLMAP", "off"), 
            setting.get("WPSCAN", "off"), 
            setting.get("NIKTO", "off"), 
            setting.get("ZAPROXY", "off"), 
            setting.get("METASPLOIT", "off")
        ]:
            if scanner.lower() == "on":
                print_error_and_exit("FULL ile diğer tarama modları aynı anda kullanılamaz.")

def print_error_and_exit(message):
    print(f"{Fore.RED}HATA: {message}{Style.RESET_ALL}")
    input(f"{Fore.RED}Program sonlandırıldı. Enter'a basarak çıkabilirsiniz.{Style.RESET_ALL}")
    sys.exit(1)

def time_tracker(task_name, duration_in_seconds):
    start_time = time.time()
    end_time = start_time + duration_in_seconds
    while time.time() < end_time:
        remaining_time = int(end_time - time.time())
        minutes, seconds = divmod(remaining_time, 60)
        print(f"[ / ] {task_name}: Kalan süre: {minutes:02}:{seconds:02}", end="\r")
        time.sleep(1)
    print(f"[🆗] {task_name}: Süresi bitti!")

# Tarama Fonksiyonları

def run_dork_file_scan():
    clear_console()
    banner()
    print("[*]\t dork scanner başlatılıyor")
    subprocess.run(["python3", "scanners/dork_file_scanner.py"])

def run_dork_scan():
    clear_console()
    banner()
    print("[*]\t dork scanner başlatılıyor")
    subprocess.run(["python3", "scanners/dork_scanner.py"])

def run_shell_scanner():
    print("[*]\t shell scanner başlatılıyor")
    subprocess.run(["python3", os.path.join("scanners", "shell_scanner.py")])

def run_sqli_shell():
    RESULTS_DIR = "results"
    RESULTS_FILE = os.path.join(RESULTS_DIR, "sqli_shell.txt")

    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    with open("results/sqli_shell.txt", "r") as f:
        urls = f.readlines()
    for url in urls:
        url = url.strip()
        subprocess.run(["sqlmap", "-u", url, "-v3", "--batch", "--threads=10", "--os-shell", "--output-dir=sql"])

def run_mini_sqli_scanner():
    print("[*]\t mini sqli scanner başlatılıyor")
    subprocess.run(["python3", os.path.join("scanners", "mini_sqli_scanner.py")])

def run_panelfinder():
    print(f"{Fore.CYAN}[+] Panel bulucu çalıştırılıyor...{Style.RESET_ALL}")
    panels = ["/admin", "/panel", "/admin/login.php", "/cpanel", "/login", "/administrator"]
    for panel in panels:
        full_url = f"{setting.get('TARGET')}{panel}"
        print(f"Denetlenen: {full_url}")

def run_wpscan():
    print(f"{Fore.CYAN}[+] WPSCAN taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["wpscan", "--url", setting.get("TARGET"), "--disable-tls-checks"]
    if setting.get("RANDOM_AGENT", "off").lower() == "on":
        user_agent = get_random_useragent()
        command += ["--user-agent", user_agent]
    subprocess.run(command)

def run_nikto():
    print(f"{Fore.CYAN}[+] NIKTO taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["nikto", "-h", setting.get("TARGET")]
    if setting.get("RANDOM_AGENT", "off").lower() == "on":
        user_agent = get_random_useragent()
        command += ["-useragent", user_agent]
    subprocess.run(command)

def run_zaproxy():
    print(f"{Fore.CYAN}[+] OWASP ZAP taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["zap-cli", "quick-scan", "--self-contained", setting.get("TARGET")]
    if setting.get("RANDOM_AGENT", "off").lower() == "on":
        user_agent = get_random_useragent()
        command += ["--user-agent", user_agent]
    subprocess.run(command)

def run_metasploit():
    print(f"{Fore.CYAN}[+] METASPLOIT taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["msfconsole", "-q", "-x", f"use auxiliary/scanner/http/http_version; set RHOSTS {setting.get('TARGET')}; run; exit"]
    subprocess.run(command)

def run_whois():
    print(f"{Fore.CYAN}[+] WHOIS taraması başlatılıyor...{Style.RESET_ALL}")
    command = ["whois", setting.get("TARGET")]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"{Fore.GREEN}[+] WHOIS Sonuçları:\n{result.stdout}{Style.RESET_ALL}")
        os.makedirs("scan_results", exist_ok=True)
        with open("scan_results/whois_result.txt", "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"{Fore.GREEN}[+] WHOIS sonuçları 'scan_results/whois_result.txt' dosyasına kaydedildi.{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] WHOIS komutu çalıştırılırken hata oluştu: {e}{Style.RESET_ALL}")

def run_autoreconx():
    script_path = os.path.join("scanners", "AutoReconX.sh")

    if not os.path.isfile(script_path):
        print(f"[!] Betik bulunamadı: {script_path}")
        return

    try:
        print("[*] AutoReconX.sh başlatılıyor...\n")
        subprocess.run(["bash", "scanners/AutoReconX.sh"], check=True)
        print("\n✅ Tarama tamamlandı.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Betik çalıştırılırken hata oluştu: {e}")
    except Exception as ex:
        print(f"[!] Genel hata: {ex}")
    
def run_full_scan():
    print(f"{Fore.CYAN}[+] FULL tarama başlatılıyor...{Style.RESET_ALL}")

    # Önce çakışmaları kontrol et
    check_conflicts()

    # AutoReconX ve shell ve panelfinder taramasını başlat
    run_autoreconx()
    run_shell_scanner()
    run_panelfinder()
    run_mini_sqli_scanner()
    run_sqli_shell()

    # Tarama araçlarını sıraya al
    scan_funcs = {
        "NIKTO": run_nikto,
        "ZAPROXY": run_zaproxy,
        "METASPLOIT": run_metasploit,
        "WHOİS": run_whois,

    }

    # Thread'li olarak her aktif aracı çalıştır
    threads = []
    for name, func in scan_funcs.items():
        if setting.get(name, "off").lower() == "on":
            print(f"[*] {name} aktif, başlatılıyor...")
            thread = threading.Thread(target=func)
            thread.start()
            threads.append(thread)

    # Tüm thread'lerin tamamlanmasını bekle
    for thread in threads:
        thread.join()

    print(f"{Fore.GREEN}[✓] FULL tarama tamamlandı.{Style.RESET_ALL}")

def işlem_sıralama():
    # Dork taramaları (varsa önce çalıştırılır)
    if setting.get("DORK_FİLE_CHECK", "off").lower() == "on":
        time_tracker("Dork File Tarama", 120)
        run_dork_file_scan()
    elif setting.get("DORK_CHECK", "off").lower() == "on":
        time_tracker("Dork Tarama", 120)
        run_dork_scan()

    # Full Scan aktifse sadece full_scan çalıştırılır
    if setting.get("FULL_SCAN", "off").lower() == "on":
        run_full_scan()
        return

    # Full scan yoksa önce autoreconx çalıştırılır
    run_autoreconx()
    run_panelfinder()
    run_shell_scanner()

    # Sonra hangi tarama araçları açıksa onlar sırasıyla çalıştırılır
    if setting.get("SQLMAP", "off").lower() == "on":
        run_sqli_shell()
        run_mini_sqli_scanner()
    if setting.get("WPSCAN", "off").lower() == "on":
        run_wpscan()
    if setting.get("NIKTO", "off").lower() == "on":
        run_nikto()
    if setting.get("ZAPROXY", "off").lower() == "on":
        run_zaproxy()
    if setting.get("METASPLOIT", "off").lower() == "on":
        run_metasploit()
    if setting.get("WHOİS", "off").lower() == "on":
        run_whois()
# Ana Çalıştırıcı
if __name__ == "__main__":
    clear_console()
    banner()
    check_setting()
    check_conflicts()
    işlem_sıralama()
