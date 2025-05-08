# -*- coding: utf-8 -*-

import re
import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import random
import platform
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict
import importlib.util
import json
import sys
import os

def output_check():
    # Klasörü kontrol et, yoksa oluştur
    if not os.path.exists("results"):
        os.makedirs("results")

# Colorama'yı başlat
colorama.init()

# Config dosyalarının yolları
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
USERAGENT_FILE = os.path.join(CONFIG_DIR, 'useragent.py')
SETTINGS_FILE = os.path.join(CONFIG_DIR, 'setting.json')

# Varsayılan değerler
OUTPUT_FILE = "results/dork_output.txt"
TEST_URL = "https://www.bing.com"
MAX_THREADS = 10
INITIAL_THROTTLE = 10
MIN_THROTTLE = 1
MAX_THROTTLE = 60  # 1 dakika maksimum bekleme

# Renk tanımlamaları
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

# Global kontrol değişkenleri
global_ban_detected = threading.Event()
global_shutdown = threading.Event()

# Thread-safe yazım için lock'lar
print_lock = threading.Lock()
file_lock = threading.Lock()
throttle_lock = threading.Lock()

def load_config():
    """Config dosyalarını yükler"""
    config = {
        'dork_file': 'dorks.txt',
        'output_file': OUTPUT_FILE
    }
    
    # setting.json yükle
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
            config.update(settings)
    except Exception as e:
        print(f"{YELLOW}[!] setting.json yüklenemedi, varsayılanlar kullanılıyor: {e}{RESET}")
    
    # useragent.py yükle
    try:
        spec = importlib.util.spec_from_file_location("useragent", USERAGENT_FILE)
        useragent_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(useragent_module)
        config['useragent'] = useragent_module
    except Exception as e:
        print(f"{RED}[!] useragent.py yüklenemedi: {e}{RESET}")
        exit(1)
    
    return config

config = load_config()

class ThrottleManager:
    def __init__(self):
        self.current_throttle = INITIAL_THROTTLE
        self.upper_limit = MAX_THROTTLE
        self.lower_limit = MIN_THROTTLE
        self.thread_throttles = defaultdict(lambda: INITIAL_THROTTLE)
    
    def adjust_throttle(self, thread_id, success):
        with throttle_lock:
            if global_ban_detected.is_set():
                return
            
            if success:
                new_throttle = max(self.thread_throttles[thread_id] * 0.9, self.lower_limit)
                self.thread_throttles[thread_id] = new_throttle
            else:
                new_throttle = min(self.thread_throttles[thread_id] * 2, self.upper_limit)
                self.thread_throttles[thread_id] = new_throttle
                self.upper_limit = new_throttle
                global_ban_detected.set()  # Tüm sistemi durdur
    
    def get_throttle(self, thread_id):
        with throttle_lock:
            return self.thread_throttles[thread_id]
    
    def reset_throttles(self):
        with throttle_lock:
            for thread_id in self.thread_throttles:
                self.thread_throttles[thread_id] = min(self.thread_throttles[thread_id] * 1.5, MAX_THROTTLE)

def clear_console():
    os.system('cls' if platform.system() == "Windows" else 'clear')

def banner():
    print(f"""{CYAN}
+----------------------------------------------------+
|                                                    |
|   _____         _   _      ___   _____             |
|  |  ___|_ _  __| | | |    / / | |___ /            |
|  | |_ / _` |/ _` | | |_  / /| |  |_ \             |
|  |  _| (_| | (_| | |  _|/ / | |___) |             |
|  |_|  \__,_|\__,_|  \__/_/  |_|____/              |
|                                                    |
+----------------------------------------------------+
    {RESET}""")
    print(f"{YELLOW}[*] Advanced DORK Scanner (Bing) - v3.3 [Configurable]{RESET}\n")
    print(f"{MAGENTA}[*] Throttle: {INITIAL_THROTTLE}s (Min: {MIN_THROTTLE}s, Max: {MAX_THROTTLE}s){RESET}")
    print(f"{MAGENTA}[*] Threads: {MAX_THREADS}{RESET}")
    print(f"{MAGENTA}[*] Dork File: {config['dork_file']}{RESET}\n")

def get_random_useragent():
    return config['useragent'].get_random_useragent()

def is_banned_or_captcha(session):
    try:
        headers = {
            "User-Agent": get_random_useragent(),
            "Accept-Language": "en-US,en;q=0.9"
        }
        with session.get(TEST_URL, headers=headers, timeout=10) as response:
            if response.status_code in [403, 429, 503] or "captcha" in response.text.lower():
                return True
            return False
    except Exception:
        return True

def url_exists_in_file(url):
    domain = urlparse(url).netloc.lower()
    if not domain:
        return False
    
    if not os.path.exists(config['output_file']):
        return False
    
    with file_lock:
        with open(config['output_file'], "r", encoding="utf-8") as f:
            for line in f:
                if domain in line.lower():
                    return True
    return False

def handle_global_ban(throttle_manager):
    """Global ban durumunu işler"""
    with print_lock:
        print(f"\n{RED}[!] GLOBAL BAN ALGILANDI! Tüm thread'ler durduruluyor...{RESET}")
        print(f"{YELLOW}[!] 60 saniye bekleniyor ve throttle süreleri artırılıyor...{RESET}\n")
    
    # Tüm thread'leri durdur
    global_shutdown.set()
    
    # 1 dakika bekle
    time.sleep(60)
    
    # Throttle'ları resetle
    throttle_manager.reset_throttles()
    
    # Kontrol flag'lerini sıfırla
    global_ban_detected.clear()
    global_shutdown.clear()
    
    with print_lock:
        print(f"{GREEN}[!] Sistemi yeniden başlatılıyor...{RESET}")

def bing_search(dork, start, session, thread_id, throttle_manager):
    if global_shutdown.is_set():
        return []
    
    current_throttle = throttle_manager.get_throttle(thread_id)
    time.sleep(current_throttle)
    
    if global_shutdown.is_set():
        return []
    
    dork = dork.replace(" ", "+")
    url = f"https://www.bing.com/search?q={dork}&first={start}"
    headers = {
        "User-Agent": get_random_useragent(),
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.bing.com/"
    }
    
    try:
        with session.get(url, headers=headers, timeout=15) as response:
            if global_shutdown.is_set():
                return []
                
            if "captcha" in response.text.lower() or response.status_code in [403, 429, 503]:
                with print_lock:
                    print(f"{RED}[!] Thread {thread_id}: Ban/Captcha detected{RESET}")
                throttle_manager.adjust_throttle(thread_id, False)
                return []
            
            results = re.findall(r'<a href="(http[s]?://[^"]+)"', response.text)
            throttle_manager.adjust_throttle(thread_id, True)
            return results
            
    except Exception as e:
        if not global_shutdown.is_set():
            with print_lock:
                print(f"{RED}[!] Thread {thread_id} error: {str(e)[:50]}...{RESET}")
            throttle_manager.adjust_throttle(thread_id, False)
        return []

def process_dork(dork, seen_domains, session, thread_id, throttle_manager):
    if global_shutdown.is_set():
        return
        
    with print_lock:
        print(f"{YELLOW}[*] Thread {thread_id}: Scanning '{dork}'{RESET}")
    
    all_results = []
    for start in range(1, 31, 10):
        if global_shutdown.is_set():
            break
            
        if is_banned_or_captcha(session):
            if not global_ban_detected.is_set():
                with print_lock:
                    print(f"{RED}[!] Thread {thread_id}: Ban detected, triggering global shutdown{RESET}")
                throttle_manager.adjust_throttle(thread_id, False)
            continue
            
        results = bing_search(dork, start, session, thread_id, throttle_manager)
        if results:
            all_results.extend(results)
    
    if global_shutdown.is_set():
        return
        
    new_urls = 0
    for url in all_results:
        if url_exists_in_file(url):
            continue
            
        domain = urlparse(url).netloc.lower()
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            with file_lock:
                with open(config['output_file'], "a", encoding="utf-8") as f:
                    f.write(url + "\n")
            new_urls += 1
    
    if not global_shutdown.is_set():
        with print_lock:
            print(f"{GREEN}[+] Thread {thread_id}: Completed '{dork}' - {new_urls} new URLs{RESET}")
            print(f"{CYAN}[i] Thread {thread_id} current throttle: {throttle_manager.get_throttle(thread_id):.1f}s{RESET}")

def main():
    clear_console()
    banner()

    # Dork dosyasını yükle
    try:
        with open(config['dork_file'], "r", encoding="utf-8") as f:
            dorklar = [line.strip() for line in f if line.strip()]
    except Exception as e:
        exit(f"{RED}[!] Dork dosyası okunamadı ({config['dork_file']}): {e}{RESET}")

    if not dorklar:
        exit(f"{RED}[!] Dork listesi boş.{RESET}")

    # Çıktı dosyasını temizle
    with open(config['output_file'], "w", encoding="utf-8"):
        pass

    seen_domains = set()
    throttle_manager = ThrottleManager()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for i, dork in enumerate(dorklar):
            if global_shutdown.is_set():
                break
                
            thread_id = i % MAX_THREADS
            futures.append(
                executor.submit(
                    process_dork, 
                    dork, 
                    seen_domains, 
                    requests.Session(), 
                    thread_id, 
                    throttle_manager
                )
            )
            time.sleep(0.5)

        # Global ban kontrolü için thread
        monitor_thread = threading.Thread(
            target=lambda: handle_global_ban(throttle_manager) if global_ban_detected.is_set() else None
        )
        monitor_thread.daemon = True
        monitor_thread.start()

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                if not global_shutdown.is_set():
                    with print_lock:
                        print(f"{RED}[!] Thread error: {e}{RESET}")

    print(f"\n{GREEN}[✓] Tüm taramalar tamamlandı. Sonuçlar: {config['output_file']}{RESET}")

if __name__ == "__main__":
    output_check()
    main()