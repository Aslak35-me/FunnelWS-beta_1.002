import sys
import os
import colorama
from colorama import Fore, Style
import platform

# config klasörünü sys.path'e ekle
sys.path.append(os.path.join(os.path.dirname(__file__), 'config'))

import setting

def clear_console():
    # İşletim sistemi adını al
    current_os = platform.system()
    
    if current_os == "Windows":
        os.system('cls')  # Windows'ta konsolu temizler
    else:
        os.system('clear')  # Linux ve MacOS'ta konsolu temizler

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
    print("[*]\t starter şuan başlatılmış durumda")
    print("======================================================\n")

def version():
    print("[*]\tFunnelWS Version BETA_1.002\n")

def check_FULL_SCAN():

    if setting.FULL_SCAN.lower() == "on":
        print("[*]\t Full scan ON durumunda.")
    elif setting.FULL_SCAN.lower() == "off":
        print("[*]\t Full scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen FULL_SCAN durumu: {setting.FULL_SCAN}")

def check_FAST_SCAN():

    if setting.FAST_SCAN.lower() == "on":
        print("[*]\t FAST scan ON durumunda.")
    elif setting.FAST_SCAN.lower() == "off":
        print("[*]\t FAST scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen FAST durumu: {setting.FAST_SCAN}")

def check_TARGET():
    print("veri setting.py den alındı")

def check_TARGET_FILE_PATH():
    print("veri setting.py den alındı")

def check_LEVEL():
    print("veri setting.py den alındı")

def check_DORK():
    print("veri setting.py den alındı")

def check_DORK_INPUT_FILE():
    print("veri setting.py den alındı")

def check_SQLMAP():

    if setting.SQLMAP.lower() == "on":
        print("[*]\t SQLMAP scan ON durumunda.")
    elif setting.SQLMAP.lower() == "off":
        print("[*]\t SQLMAP scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen SQLMAP durumu: {setting.SQLMAP}")

def check_WPSCAN():

    if setting.WPSCAN.lower() == "on":
        print("[*]\t WPSCAN scan ON durumunda.")
    elif setting.WPSCAN.lower() == "off":
        print("[*]\t WPSCAN scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen WPSCAN durumu: {setting.WPSCAN}")

def check_NIKTO():

    if setting.NIKTO.lower() == "on":
        print("[*]\t NIKTO scan ON durumunda.")
    elif setting.NIKTO.lower() == "off":
        print("[*]\t NIKTO scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen NIKTO durumu: {setting.NIKTO}")
    
def check_ZAPROXY():

    if setting.ZAPROXY.lower() == "on":
        print("[*]\t ZAPROXY scan ON durumunda.")
    elif setting.ZAPROXY.lower() == "off":
        print("[*]\t ZAPROXY scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen ZAPROXY durumu: {setting.ZAPROXY}")

def check_METASPLOIT():

    if setting.METASPLOIT.lower() == "on":
        print("[*]\t METASPLOIT scan ON durumunda.")
    elif setting.METASPLOIT.lower() == "off":
        print("[*]\t METASPLOIT scan OFF durumunda.")
    else:
        print(f"[*]\t Bilinmeyen METASPLOIT durumu: {setting.METASPLOIT}")

def check_REPORT_TYPE():
    print("veri setting.py den alındı")

def check_es_parametreler():

    if setting.FAST_SCAN.lower() == "on":
        if setting.FULL_SCAN.lower() == "on":
            print(f"{Fore.RED}HATA: FAST ve FULL parametreleri aynı anda kullanılamaz{Style.RESET_ALL}")
            print(f"{Fore.RED}HATA code: parametre(1){Style.RESET_ALL}")
            hatadandolayıexit = input(f"{Fore.RED}HATA aldınız işlem sonlandırıldı lütfen programı kapatıp tekrar açının{Style.RESET_ALL}")

if __name__ == "__main__":

    clear_console()
    banner()
    check_FULL_SCAN()
    check_FAST_SCAN()
    check_TARGET()
    check_TARGET_FILE_PATH()
    check_LEVEL()
    check_DORK()
    check_DORK_INPUT_FILE()
    check_SQLMAP()
    check_WPSCAN()
    check_NIKTO()
    check_ZAPROXY()
    check_METASPLOIT()
    check_REPORT_TYPE()
    check_es_parametreler()
