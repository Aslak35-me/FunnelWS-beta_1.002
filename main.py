import argparse
import os

SETTINGS_FILE = "config/setting.py"

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

def version():
    print("[*]\tFunnelWS Version 1.002\n")

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
    ╚══════════════════════════════════════════════════════╝
    """)

def target(target):
    print(f"[+] Hedef: {target}")
    updated_lines = []
    found = False

    # settings.py dosyasını oku
    with open(SETTINGS_FILE, "r") as f:
        for line in f:
            if line.startswith("TARGET"):
                updated_lines.append(f'TARGET = "{target}"\n')
                found = True
            else:
                updated_lines.append(line)

    # Eğer TARGET yoksa ekle
    if not found:
        updated_lines.append(f'TARGET = "{target}"\n')

    # Dosyayı güncelle
    with open(SETTINGS_FILE, "w") as f:
        f.writelines(updated_lines)

def target_input(file_path):
    updated_lines = []
    found = False
    file_name = os.path.basename(file_path)

    if not os.path.exists(SETTINGS_FILE):
        print(f"[!] Hata: Ayar dosyası bulunamadı: {SETTINGS_FILE}")
        print(f"[!] Lütfen hatayı düzeltin ve tekrar deneyin")
        return

    # settings.py dosyasını oku
    with open(SETTINGS_FILE, "r") as f:
        for line in f:
            if line.startswith("TARGET_FILE_PATH"):
                updated_lines.append(f'TARGET_FILE_PATH = "{file_path}"\n')
                found = True
            else:
                updated_lines.append(line)

    # Eğer TARGET_FILE_PATH yoksa ekle
    if not found:
        updated_lines.append(f'TARGET_FILE_PATH = "{file_path}"\n')

    # Dosyayı güncelle
    with open(SETTINGS_FILE, "w") as f:
        f.writelines(updated_lines)

    print(f"[+] TARGET_FILE_PATH update edildi : {file_path}")
    print(f"[+] File name: {file_name}")

def level(lv):
    print(f"[+] Seviye: {lv}")
    updated_lines = []
    found = False

    if not os.path.exists(SETTINGS_FILE):
        print(f"[!] Hata: Ayar dosyası bulunamadı: {SETTINGS_FILE}")
        return

    try:
        lv = int(lv)
        if lv < 1 or lv > 5:
            print("[!] Geçersiz seviye. Lütfen 1 ile 5 arasında bir değer girin.")
            return
    except ValueError:
        print("[!] Seviye bir sayı olmalıdır.")
        return

    # settings.py dosyasını oku ve LEVEL satırını bulup değiştir
    with open(SETTINGS_FILE, "r") as f:
        for line in f:
            if line.startswith("LEVEL"):
                updated_lines.append(f"LEVEL = {lv}\n")
                found = True
            else:
                updated_lines.append(line)

    # Eğer LEVEL satırı yoksa ekle
    if not found:
        updated_lines.append(f"LEVEL = {lv}\n")

    # Dosyayı güncelle
    with open(SETTINGS_FILE, "w") as f:
        f.writelines(updated_lines)

    print(f"[+] LEVEL güncellendi: {lv}")

def set_fast_scan_mode(is_enabled):
    mode = "on" if is_enabled else "off"
    print(f"[+] FAST_SCAN modu: {mode}")
    updated_lines = []
    found = False
    if not os.path.exists(SETTINGS_FILE):
        print(f"[!] Hata: Ayar dosyası bulunamadı: {SETTINGS_FILE}")
        return
    with open(SETTINGS_FILE, "r") as f:
        for line in f:
            if line.startswith("FAST_SCAN"):
                updated_lines.append(f'FAST_SCAN = "{mode}"\n')
                found = True
            else:
                updated_lines.append(line)
    if not found:
        updated_lines.append(f'FAST_SCAN = "{mode}"\n')
    with open(SETTINGS_FILE, "w") as f:
        f.writelines(updated_lines)
    print(f"[+] FAST_SCAN ayarlanırken bir sorun çıkmadı mod :  {mode}")

def run_fast_scan():
    print("[*] Hızlı tarama seçeneği seçildi!")

def full_scan(): ###daha sonra ayarlancak 
    print("[*] Detaylı tarama başlatıldı...")

def dork_search(dork): ###daha sonra ayarlancak
    print(f"[+] Dork ile arama: {dork}")

def dork_input(file): ###daha sonra ayarlancak
    print(f"[+] Dork listesi dosyadan alınıyor: {file}")

# Açık türleri ###daha sonra ayarlancak
def scan_sqli():###daha sonra ayarlancak
    print("[*] SQLi taraması başlatıldı...")

def scan_xxs():###daha sonra ayarlancak
    print("[*] XXS taraması başlatıldı...")

# Tool çağrıları
def use_sqlmap():
    print("[*] SQLMap aracı kullanılıyor...")

def use_nmap():
    print("[*] Nmap aracı kullanılıyor...")

def use_wpscan():
    print("[*] WPScan aracı kullanılıyor...")

def use_nikto():
    print("[*] Nikto aracı kullanılıyor...")

def use_zaproxy():
    print("[*] Zaproxy aracı kullanılıyor...")

def use_metasploit():
    print("[*] Metasploit aracı kullanılıyor...")

# Raporlama
def report(report_type):
    print(f"[*] Rapor tipi: {report_type}")
    updated_lines = []
    found = False

    if not os.path.exists(SETTINGS_FILE):
        print(f"[!] Hata: Ayar dosyası bulunamadı: {SETTINGS_FILE}")
        return

        with open(SETTINGS_FILE, "r") as f:
            for line in f:
                if line.startswith("REPORT_TYPE"):
                    updated_lines.append(f'REPORT_TYPE = "{report_type}"')
                    found = True
                else:
                    updated_lines.append(line)

    if not found:
        updated_lines.append(f'REPORT_TYPE = "{report_type}"')

        with open(SETTINGS_FILE, "w") as f:
            f.writelines(updated_lines)

    print("[+] Rapor tipi ayarlandı: {report_type}")

def use_tor(): ###daha sonra ayarlancak

    print("[*] Tor üzerinden gizli tarama başlatıldı...")

def use_random_agent():
    print("[+] random agent kullanılıcak")

def set_random_agent_mode(is_enabled):
    mode = "on" if is_enabled else "off"
    print(f"[+] RANDOM_AGENT modu: {mode}")
    updated_lines = []
    found = False

    if not os.path.exists(SETTINGS_FILE):
        print(f"[!] Hata: Ayar dosyası bulunamadı: {SETTINGS_FILE}")
        return

    with open(SETTINGS_FILE, "r") as f:
        for line in f:
            if line.startswith("RANDOM_AGENT"):
                updated_lines.append(f'RANDOM_AGENT = "{mode}"\n')
                found = True
            else:
                updated_lines.append(line)

    if not found:
        updated_lines.append(f'RANDOM_AGENT = "{mode}"\n')

    with open(SETTINGS_FILE, "w") as f:
        f.writelines(updated_lines)

    print(f"[+] RANDOM_AGENT ayarlandı: {mode}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FunnelWS - Web Vulnerability Scanner", add_help=False)

    parser.add_argument("--target", "--t", help="Hedef domain/IP", dest="target")
    parser.add_argument("--target-input", "--t-input", help="Hedef listesini içeren dosya", dest="target_input")
    parser.add_argument("--level", "--lv", help="Tarama seviyesi")
    parser.add_argument("--fast", action="store_true", help="Hızlı tarama modu")
    parser.add_argument("--full", "--all", action="store_true", help="Detaylı tarama modu")

    parser.add_argument("--dork", help="Dork ile site arama")
    parser.add_argument("--dork-input", help="Dork listesini içeren dosya")

    # Açık taramaları
    parser.add_argument("--sqli", action="store_true", help="SQLi açığı taraması")
    parser.add_argument("--xxs", action="store_true", help="XXS açığı taraması")

    # Araçlar
    parser.add_argument("--sqlmap", "--tool-sqlmap", action="store_true", help="SQLMap kullan")
    parser.add_argument("--nmap", "--tool-nmap", action="store_true", help="Nmap kullan")
    parser.add_argument("--wpscan", "--tool-wpscan", action="store_true", help="WPScan kullan")
    parser.add_argument("--nikto", "--tool-nikto", action="store_true", help="Nikto kullan")
    parser.add_argument("--zaproxy", "--tool-zaproxy", action="store_true", help="Zaproxy kullan")
    parser.add_argument("--metasploit", "--tool-metasploit", action="store_true", help="Metasploit kullan")

    # Raporlama
    parser.add_argument("--report", choices=["json", "html", "pdf"], help="Rapor formatı")
    parser.add_argument("--report-html", action="store_true", help="HTML raporu")
    parser.add_argument("--report-json", action="store_true", help="JSON raporu")
    parser.add_argument("--report-pdf", action="store_true", help="PDF raporu")

    # diğer
    parser.add_argument("--banner", action="store_true", help="Banner göster")
    parser.add_argument("--version", "--v", action="store_true", help="Sürüm bilgisi")
    parser.add_argument("--help", "--h", action="store_true", help="Yardım menüsü")
    parser.add_argument("--tor", action="store_true", help="Tor üzerinden tarama")
    parser.add_argument("--user-agent", "--random-agent", action="store_true", help="user agent ile taramalar yapar")

    args = parser.parse_args()

    # Argümanlara göre fonksiyonları çalıştır
    if args.banner:
        banner()
    if args.version:
        version()
    if args.help:
        help_menu()
    if args.target:
        target(args.target)
    if args.target_input:
        target_input(args.target_input)
    if args.level:
        level(args.level)
    if args.fast:
        run_fast_scan()
    set_fast_scan_mode(args.fast)

    if args.full:
        full_scan()
    if args.dork:
        dork_search(args.dork)
    if args.dork_input:
        dork_input(args.dork_input)

    if args.sqli:
        scan_sqli()
    if args.xxs:
        scan_xxs()

    if args.sqlmap:
        use_sqlmap()
    if args.nmap:
        use_nmap()
    if args.wpscan:
        use_wpscan()
    if args.nikto:
        use_nikto()
    if args.zaproxy:
        use_zaproxy()
    if args.metasploit:
        use_metasploit()

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
    set_random_agent_mode(args.user_agent)

