#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Core modüllerini ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.useragent import get_random_useragent
from config.version_detector import detect_versions
from config.target_loader import load_targets

init(autoreset=True)

class AdvancedVulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_random_useragent()})
        self.vulnerabilities = []
        self.technologies = {}
        self.load_settings()
        self.load_vulnerability_database()
        
    def load_settings(self):
        """Ayarları yükler"""
        with open('config/setting.json', 'r') as f:
            self.settings = json.load(f)
        
        self.rate_limit_wait = self.settings['RATE_LIMIT_WAIT']
        self.max_retries = self.settings['MAX_RETRIES']
        self.timeout = self.settings['TIMEOUT']

def load_vulnerability_database(self):
    """Vulnerability veritabanını yükler"""
    self.vuln_db = {}
    base_path = os.path.join('files', 'vuln')
    
    # CVE veritabanını yükle
    cve_path = os.path.join(base_path, 'cve')
    if os.path.exists(cve_path):
        for tech_file in os.listdir(cve_path):
            if tech_file.endswith('.json'):
                tech_name = tech_file.split('.')[0]
                with open(os.path.join(cve_path, tech_file), 'r') as f:
                    self.vuln_db.setdefault(tech_name, {}).update({'cve': json.load(f)})
    else:
        print(f"{Fore.YELLOW}[!] CVE dizini bulunamadı: {cve_path}{Style.RESET_ALL}")
    
    # Exploit-DB veritabanını yükle
    exploit_path = os.path.join(base_path, 'exploit-db')
    if os.path.exists(exploit_path):
        for tech_file in os.listdir(exploit_path):
            if tech_file.endswith('.json'):
                tech_name = tech_file.split('.')[0]
                with open(os.path.join(exploit_path, tech_file), 'r') as f:
                    self.vuln_db.setdefault(tech_name, {}).update({'exploit-db': json.load(f)})
    else:
        print(f"{Fore.YELLOW}[!] Exploit-DB dizini bulunamadı: {exploit_path}{Style.RESET_ALL}")
    
    # NVD veritabanını yükle
    nvd_path = os.path.join(base_path, 'nvd')
    if os.path.exists(nvd_path):
        for tech_file in os.listdir(nvd_path):
            if tech_file.endswith('.json'):
                tech_name = tech_file.split('.')[0]
                with open(os.path.join(nvd_path, tech_file), 'r') as f:
                    self.vuln_db.setdefault(tech_name, {}).update({'nvd': json.load(f)})
    else:
        print(f"{Fore.YELLOW}[!] NVD dizini bulunamadı: {nvd_path}{Style.RESET_ALL}")

    def scan_target(self, target):
        """Tek bir hedefi tarar"""
        self.target = target if target.startswith(('http://', 'https://')) else f'http://{target}'
        self.technologies = {}
        self.vulnerabilities = []
        
        print(f"\n{Fore.CYAN}=== {self.target} TARANIYOR ==={Style.RESET_ALL}")
        
        if not self.wait_for_access():
            return False
        
        self.detect_technologies()
        self.scan_for_vulnerabilities()
        self.generate_report()
        return True

    def detect_technologies(self):
        """Web teknolojilerini ve versiyonlarını tespit eder"""
        print(f"{Fore.BLUE}[*] Teknoloji ve versiyon tespiti yapılıyor...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            self.technologies = detect_versions(response)
            
            if self.technologies:
                print(f"{Fore.GREEN}[+] Tespit edilen teknolojiler:{Style.RESET_ALL}")
                for tech, details in self.technologies.items():
                    print(f"  {tech}: {details.get('version', 'bilinmiyor')}")
                    print(f"    Kategori: {details.get('category', 'bilinmiyor')}")
                    print(f"    Güvenilirlik: {details.get('confidence', 'bilinmiyor')}")
            else:
                print(f"{Fore.YELLOW}[-] Teknoloji tespit edilemedi{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Teknoloji tespit hatası: {e}{Style.RESET_ALL}")

    def scan_for_vulnerabilities(self):
        """Tespit edilen teknolojilere göre zafiyet taraması yapar"""
        if not self.technologies:
            print(f"{Fore.YELLOW}[-] Teknoloji bilgisi yok, genel tarama yapılamıyor{Style.RESET_ALL}")
            return
        
        print(f"{Fore.BLUE}[*] Teknoloji tabanlı zafiyet taraması başlatılıyor...{Style.RESET_ALL}")
        
        for tech, details in self.technologies.items():
            tech_name = tech.lower()
            version = details.get('version', '')
            
            # Teknoloji için CVE ara
            if tech_name in self.vuln_db:
                self.check_technology_vulnerabilities(tech_name, version)
            else:
                print(f"{Fore.YELLOW}[-] {tech} için zafiyet veritabanı bulunamadı{Style.RESET_ALL}")

    def check_technology_vulnerabilities(self, tech_name, version):
        """Belirli bir teknoloji için zafiyet kontrolü yapar"""
        print(f"{Fore.MAGENTA}[*] {tech_name} ({version}) için zafiyet kontrolü yapılıyor...{Style.RESET_ALL}")
        
        # CVE kontrolü
        if 'cve' in self.vuln_db[tech_name]:
            for cve in self.vuln_db[tech_name]['cve']['vulnerabilities']:
                if self.is_version_affected(version, cve.get('affected_versions', '*')):
                    print(f"{Fore.YELLOW}[!] Potansiyel {cve['id']}: {cve['description']}{Style.RESET_ALL}")
                    if self.verify_vulnerability(cve):
                        self.record_vulnerability(tech_name, version, cve, 'CVE')
        
        # Exploit-DB kontrolü
        if 'exploit-db' in self.vuln_db[tech_name]:
            for exploit in self.vuln_db[tech_name]['exploit-db']['exploits']:
                if self.is_version_affected(version, exploit.get('affected_versions', '*')):
                    print(f"{Fore.YELLOW}[!] Potansiyel Exploit-DB ID: {exploit['id']}{Style.RESET_ALL}")
                    self.record_vulnerability(tech_name, version, exploit, 'Exploit-DB')

    def is_version_affected(self, detected_version, affected_range):
        """Versiyonun etkilenen aralıkta olup olmadığını kontrol eder"""
        if affected_range == '*' or not detected_version:
            return True
        
        # Basit versiyon karşılaştırma (geliştirilebilir)
        return detected_version in affected_range

    def verify_vulnerability(self, cve):
        """Zafiyetin gerçekten var olup olmadığını doğrular"""
        try:
            test_url = urljoin(self.target, cve.get('test_path', '/'))
            
            if cve.get('method', 'GET') == 'POST':
                response = self.session.post(
                    test_url,
                    headers=cve.get('headers', {}),
                    data=cve.get('data', {}),
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    test_url,
                    headers=cve.get('headers', {}),
                    timeout=self.timeout
                )
            
            if cve.get('detection_method') == 'status_code':
                return response.status_code == cve.get('expected_code')
            elif cve.get('detection_method') == 'string_match':
                return cve.get('expected_string') in response.text
            else:
                return False
                
        except Exception:
            return False

    def record_vulnerability(self, tech_name, version, vuln, vuln_type):
        """Tespit edilen zafiyeti kaydeder"""
        entry = {
            'type': vuln_type,
            'id': vuln['id'],
            'technology': tech_name,
            'version': version,
            'description': vuln.get('description', ''),
            'severity': vuln.get('severity', 'unknown'),
            'cvss': vuln.get('cvss_score', 'unknown'),
            'references': vuln.get('references', [])
        }
        
        if vuln_type == 'CVE':
            print(f"{Fore.RED}[!] DOĞRULANDI: {vuln['id']} - {vuln['description']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] EXPLOIT BULUNDU: {vuln['id']}{Style.RESET_ALL}")
        
        self.vulnerabilities.append(entry)

    def generate_report(self):
        """Detaylı rapor oluşturur"""
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] Zafiyet bulunamadı{Style.RESET_ALL}")
            return
            
        report = {
            'target': self.target,
            'scan_date': time.strftime("%d.%m.%Y %H:%M:%S"),
            'detected_technologies': self.technologies,
            'vulnerabilities': self.vulnerabilities,
            'stats': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }
        
        filename = f"vuln_report_{self.target.replace('://', '_')}_{int(time.time())}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
            
        print(f"{Fore.GREEN}[+] Rapor oluşturuldu: {filename}{Style.RESET_ALL}")

    def wait_for_access(self):
        """Rate limit kontrolü ve bekleme"""
        retries = 0
        while retries < self.max_retries:
            try:
                response = self.session.get(urljoin(self.target, '/'), timeout=self.timeout)
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', self.rate_limit_wait))
                    print(f"{Fore.RED}[!] Rate limit: {retry_after}s bekleniyor...{Style.RESET_ALL}")
                    time.sleep(retry_after)
                    retries += 1
                    continue
                return True
            except requests.exceptions.RequestException:
                retries += 1
                time.sleep(self.rate_limit_wait)
        
        print(f"{Fore.RED}[!] Max retries reached. Target may have blocked us.{Style.RESET_ALL}")
        return False

def main():
    scanner = AdvancedVulnerabilityScanner()
    targets = load_targets()
    
    for target in targets:
        try:
            scanner.scan_target(target)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Tarama kullanıcı tarafından durduruldu{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}[!] {target} taranırken hata: {e}{Style.RESET_ALL}")
            continue

if __name__ == '__main__':
    main()