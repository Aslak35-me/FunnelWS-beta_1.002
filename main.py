import argparse
import json
import os
import subprocess
import sys
from colorama import Fore, Style
import platform

SETTINGS_FILE = "config/setting.json"

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

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
    print("[*]\tFunnelWS Web Vulnerability Scanner")
    version()
    print("======================================================\n")

def version():
    print("[*]\tFunnelWS Version BETA_1.002\n")

def help_menu():
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║            FunnelWS - Web Vulnerability Scanner      ║
    ╠══════════════════════════════════════════════════════╣
    ║  Temel Kullanım                                      ║
    ║  python main.py [seçenekler]                         ║
    ╠══════════════════════════════════════════════════════╣
    ║  Hedef Belirleme                                     ║
    ║  --target, --t <hedef>          Tek bir hedef girin  ║
    ║  --target-input, --t-input <dosya> Liste dosyası     ║
    ╠══════════════════════════════════════════════════════╣
    ║  Tarama Ayarları                                     ║
    ║  --level <1-5>               Tarama derinliği seçin  ║
    ║  --fast                     Hızlı tarama             ║
    ║  --full, --all              Detaylı, kapsamlı tarama ║
    ╠══════════════════════════════════════════════════════╣
    ║  Dork Tabanlı Tarama                                 ║
    ║  --dork <dork>              Tek bir dork ile arama   ║
    ║  --dork-input <dosya>       Dork listesi girin       ║
    ╠══════════════════════════════════════════════════════╣
    ║  Açık Taramaları                                     ║
    ║  --sqli                     SQL injection taraması   ║
    ║  --xxs                      Cross-site scripting     ║
    ╠══════════════════════════════════════════════════════╣
    ║  Harici Güvenlik Araçları                            ║
    ║  --sqlmap                  SQLMap ile analiz         ║
    ║  --nmap                    Nmap ile port tarama      ║
    ║  --wpscan                  WPScan ile WP tarama      ║
    ║  --nikto                   Nikto ile sunucu analizi  ║
    ║  --zaproxy                 OWASP ZAP Proxy taraması  ║
    ║  --metasploit              Metasploit entegrasyonu   ║
    ╠══════════════════════════════════════════════════════╣
    ║  Raporlama Ayarları                                  ║
    ║  --report <json/html/pdf>  Rapor biçimi seçin        ║
    ║  --report-html             HTML formatında rapor     ║
    ║  --report-json             JSON formatında rapor     ║
    ║  --report-pdf              PDF formatında rapor      ║
    ╠══════════════════════════════════════════════════════╣
    ║  Diğer Seçenekler                                    ║
    ║  --tor                      Tor ile gizli tarama     ║
    ║  --banner                   Banner'ı gösterir        ║
    ║  --version, --v             Sürüm bilgisini verir    ║
    ║  --help, --h                Yardım menüsünü gösterir ║
    ║  --start                    ana starter/başlatıcı    ║ 
    ╚══════════════════════════════════════════════════════╝
    """)

def target(target_value):
    settings = load_settings()
    settings["TARGET"] = target_value
    save_settings(settings)
    print(f"[+] TARGET güncellendi: {target_value}")

def use_targe_check(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["TARGET_FİLE_CHECK"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] TARGET FİLE modu güncellendi: {mode}")

def target_input(file_path):
    settings = load_settings()
    file_name = os.path.basename(file_path)
    settings["TARGET_FILE_PATH"] = file_path
    save_settings(settings)
    print(f"[+] TARGET_FILE_PATH update edildi : {file_path}")
    print(f"[+] File name: {file_name}")

def level(lv):
    try:
        lv = int(lv)
        if lv < 1 or lv > 5:
            print("[!] Geçersiz seviye. Lütfen 1 ile 5 arasında bir değer girin.")
            return
    except ValueError:
        print("[!] Seviye bir sayı olmalıdır.")
        return

    settings = load_settings()
    settings["LEVEL"] = lv
    save_settings(settings)
    print(f"[+] LEVEL güncellendi: {lv}")

def set_fast_scan_mode(is_enabled):
    mode = "on" if is_enabled else "off"
    settings = load_settings()
    settings["FAST_SCAN"] = mode
    save_settings(settings)
    print(f"[+] FAST_SCAN ayarlandı: {mode}")

def run_fast_scan():
    print("[*] Hızlı tarama seçeneği seçildi!")

def full_scan(is_enabled):
    mode = "on" if is_enabled else "off"
    settings = load_settings()
    settings["FULL_SCAN"] = mode
    save_settings(settings)
    print(f"[+] FULL_SCAN ayarlandı: {mode}")

def run_full_scan():
    print("[*] Hızlı tarama seçeneği seçildi!")

def use_dork_check(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["DORK_CHECK"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] DORK CHECK modu güncellendi: {mode}")

def dork_search(dork):
    settings = load_settings()
    settings["DORK"] = dork
    save_settings(settings)
    print(f"[+] DORK ayarlandı: {dork}")

def dork_input(dork_file):
    settings = load_settings()
    file_name = os.path.basename(dork_file)
    settings["DORK_INPUT_FILE"] = dork_file
    save_settings(settings)
    print(f"[+] DORK_INPUT_FILE update edildi : {dork_file}")
    print(f"[+] File name: {file_name}")

def use_dork_file_check(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["DORK_FİLE_CHECK"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] DORK_FİLE_CHECK modu güncellendi: {mode}")

def scan_sqli():
    print_error_and_exit("[*] açık seçme işlemi şuanlık kullanılamıyor... \n [*] lütfen açık seçme (sqli) parametresini kullanmayınız!")

def scan_xxs():
    print_error_and_exit("[*] açık seçme işlemi şuanlık kullanılamıyor... \n [*] lütfen açık seçme (xss) parametresini kullanmayınız!")

def use_sqlmap(is_enabled):

    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # SQLMAP modunu güncelle
    settings["SQLMAP"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] SQLMAP modu güncellendi: {mode}")

def run_use_sqlmap():
    print("[*] sqlmap aracı kullanılacak !")

def use_nmap(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["NMAP"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] NMAP modu güncellendi: {mode}")

def run_use_nmap():
    print("[*] NMAP aracı kullanılacak !")

def use_wpscan(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["WPSCAN"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] WPSCAN modu güncellendi: {mode}")

def run_use_wpscan():
    print("[*] WP-SCAN aracı kullanılacak !")

def use_nikto(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["NIKTO"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] NİKTO modu güncellendi: {mode}")

def run_use_nikto():
    print("[*] Nikto aracı kullanılacak !")

def use_zaproxy(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["ZAPROXY"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] ZAPROXY modu güncellendi: {mode}")

def run_use_zaproxy():
    print("[*] ZAPROXY (OWASP) aracı kullanılacak !")

def use_metasploit(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["METASPLOIT"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] METASPLOİT modu güncellendi: {mode}")

def run_use_metasploit():
    print("[*] METASPLOİT aracı kullanılacak !")

def run_use_whois():
    print("[*] WHOİS aracı kullanılacak !")

def use_whois(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["WHOIS"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] WHOİS modu güncellendi: {mode}")

def report(report_type):
    print(f"[*] Rapor mode: {report_type}")

    # JSON dosyasını oku (varsa)
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # REPORT_TYPE değerini güncelle
    settings["REPORT_TYPE"] = report_type

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] Rapor mode ayarlandı: {report_type}")

def use_tor():
    print_error_and_exit("[*] Tor şuanlık kullanılamıyor... \n [*] lütfen TOR parametresini kullanmayınız!")

def use_random_agent():
    print("[+] random agent kullanılıcak")

def use_random_agent_mode(is_enabled):
    mode = "on" if is_enabled else "off"

    # Dosya varsa oku, yoksa boş sözlük başlat
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            try:
                settings = json.load(f)
            except json.JSONDecodeError:
                settings = {}
    else:
        settings = {}

    # NMAP modunu güncelle
    settings["RANDOM_AGENT"] = mode

    # JSON dosyasına yaz
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    print(f"[+] RANDOM AGENT modu güncellendi: {mode}")

def print_error_and_exit(message):
    print(f"{Fore.RED}HATA: {message}{Style.RESET_ALL}")
    input(f"{Fore.RED}HATA nedeniyle işlem sonlandırıldı. Programı kapatıp tekrar açınız.{Style.RESET_ALL}")
    sys.exit(1)

def clear_console():
    current_os = platform.system()
    os.system('cls' if current_os == "Windows" else 'clear')

def reset_settings_to_default():
    default_settings = {
        "FAST_SCAN": "off",
        "FULL_SCAN": "off",
        "SQLMAP": "off",
        "NMAP": "off",
        "WPSCAN": "off",
        "NIKTO": "off",
        "ZAPROXY": "off",
        "METASPLOIT": "off",
        "RANDOM_AGENT": "off",
        "WHOİS": "off",
        "DORK_CHECK": "off",
        "DORK_FİLE_CHECK": "off",
        "sqlmap_threads": 10,
        "sqlmap_level": 3,
        "sqlmap_risk": 3,
        "sqlmap_timeout": 300,
        "request_timeout": 10,
        "shell_upload_path": "/var/www/html/shell.php",
        "test_command": "whoami",
        "RATE_LIMIT_WAIT": 180,
        "MAX_RETRIES": 3,
        "TIMEOUT": 10
        }
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(default_settings, f, indent=4, ensure_ascii=False)
    
def start():
    clear_console()
    banner()
    print("[*]\t starter başlatılıyor")
    subprocess.run(["python3", "starter.py"])

    
if __name__ == "__main__":
    clear_console()
    reset_settings_to_default()
    parser = argparse.ArgumentParser(description="FunnelWS - Web Vulnerability Scanner", add_help=False)

    # Tüm argüman tanımları
    parser.add_argument("--target", "--t", help="Hedef domain/IP", dest="target")
    parser.add_argument("--target-input", "--t-input", help="Hedef listesini içeren dosya", dest="target_input")
    
    parser.add_argument("--level", "--lv", help="Tarama seviyesi")
    parser.add_argument("--fast", action="store_true", help="Hızlı tarama modu")
    parser.add_argument("--full", "--all", action="store_true", help="Detaylı tarama modu")

    parser.add_argument("--dork", help="Dork ile site arama")
    parser.add_argument("--dork-input", help="Dork listesini içeren dosya")

    parser.add_argument("--sqli", action="store_true", help="SQLi açığı taraması")
    parser.add_argument("--xxs", action="store_true", help="XXS açığı taraması")

    parser.add_argument("--sqlmap", "--tool-sqlmap", action="store_true", help="SQLMap kullan")
    parser.add_argument("--nmap", "--tool-nmap", action="store_true", help="Nmap kullan")
    parser.add_argument("--wpscan", "--tool-wpscan", action="store_true", help="WPScan kullan")
    parser.add_argument("--nikto", "--tool-nikto", action="store_true", help="Nikto kullan")
    parser.add_argument("--zaproxy", "--tool-zaproxy", action="store_true", help="Zaproxy kullan")
    parser.add_argument("--metasploit", "--tool-metasploit", action="store_true", help="Metasploit kullan")
    parser.add_argument("--whois", "--tool-whois", action="store_true", help="whois kullan")

    parser.add_argument("--report", choices=["json", "html", "pdf"], help="Rapor formatı")
    parser.add_argument("--report-html", action="store_true", help="HTML raporu")
    parser.add_argument("--report-json", action="store_true", help="JSON raporu")
    parser.add_argument("--report-pdf", action="store_true", help="PDF raporu")

    parser.add_argument("--banner", action="store_true", help="Banner göster")
    parser.add_argument("--version", "--v", action="store_true", help="Sürüm bilgisi")
    parser.add_argument("--help", "--h", action="store_true", help="Yardım menüsü")
    parser.add_argument("--tor", action="store_true", help="Tor üzerinden tarama")
    parser.add_argument("--user-agent", "--random-agent", action="store_true", help="user agent ile taramalar yapar")

    parser.add_argument("--threads", type=int, default=5, help="İş parçacığı (thread) sayısı (varsayılan: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="İstek zaman aşımı (saniye) (varsayılan: 10)")
    parser.add_argument("--verbose", action="store_true", help="Detaylı çıktı ver")
    
    parser.add_argument("--start", action="store_true", help="ana başlatıcı/starter")

    args = parser.parse_args()


    # Eğer ayar dosyası yoksa, varsayılan ayarlarla oluştur
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w") as f:
            for key, value in default_settings.items():
                f.write(f'{key} = "{value}"\n')

    # Argümanlara göre fonksiyonları çalıştır
    if args.banner:
        banner()
    if args.version:
        banner()
    if args.help:
        banner()
        help_menu()
    if args.target:
        use_targe_check(False)
        target(args.target)
    if args.target_input:
        use_targe_check(True)
        target_input(args.target_input)
    if args.level:
        level(args.level)
    if args.fast:
        run_fast_scan()
        set_fast_scan_mode(True)  # "on" olarak ayarla
    if args.full:
        run_full_scan()
        full_scan(True)  # "on" olarak ayarla
    if args.dork:
        use_dork_check(True)
        dork_search(args.dork)
    if args.dork_input:
        use_dork_file_check(True)
        dork_input(args.dork_input)
    if args.sqli:
        scan_sqli()
    if args.xxs:
        scan_xxs()
    if args.sqlmap:
        run_use_sqlmap()
        use_sqlmap(True)  # "on" olarak ayarla
    if args.nmap:
        run_use_nmap()
        use_nmap(True)  # "on" olarak ayarla
    if args.wpscan:
        run_use_wpscan()
        use_wpscan(True)  # "on" olarak ayarla
    if args.nikto:
        run_use_nikto()
        use_nikto(True)  # "on" olarak ayarla
    if args.zaproxy:
        run_use_zaproxy()
        use_zaproxy(True)  # "on" olarak ayarla
    if args.metasploit:
        run_use_metasploit()
        use_metasploit(True)  # "on" olarak ayarla
    if args.whois:
        run_use_whois()
        use_whois(True)  # "on" olarak ayarla    
    if args.report:
        report(args.report)
    if args.report_html:
        report("html")
    if args.report_json:
        report("json")
    if args.report_pdf:
        report("pdf")
    if args.user_agent:
        use_random_agent()
        use_random_agent_mode(True)  # "on" olarak ayarla
    if args.start:
        start()