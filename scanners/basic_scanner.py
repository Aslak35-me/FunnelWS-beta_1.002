import sys
from pathlib import Path

# 1. Proje yapılandırması - EN ÜSTTE OLMALI
BASE_DIR = Path(__file__).parent.parent  # /home/kali/FunnelWS-beta_1.002
sys.path.append(str(BASE_DIR))  # Python yoluna kök dizini ekle

# 2. Ayarları yükle
SETTING_PATH = BASE_DIR / 'config' / 'setting.json'
try:
    with open(SETTING_PATH, 'r', encoding='utf-8') as f:
        setting = json.load(f)
except FileNotFoundError:
    print(f"[HATA] setting.json bulunamadı: {SETTING_PATH}")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"[HATA] Geçersiz JSON formatı: {SETTING_PATH}")
    sys.exit(1)

# 3. Gerekli kütüphaneler
import requests
import socks
import socket
import dns.resolver
import time
import random
import subprocess
import ssl
import json
import os
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
import textwrap
from config.useragent import get_random_useragent

# 4. Ayarlardan değerleri al
TARGET_FILE_PATH = setting.get("TARGET_FILE_PATH")
TARGET = setting.get("TARGET")
TARGET_FILE_CHECK = setting.get("TARGET_FILE_CHECK")

# 5. Renkleri başlat
init(autoreset=True)

class WebTechScanner:
    def __init__(self, target):
        self.target = self.normalize_target(target)
        self.headers = {
            'User-Agent': get_random_useragent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.results = {
            'target': self.target,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'technologies': []
        }

    def normalize_target(self, target):
        """Hedef URL'yi normalize eder"""
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        return target

    def run_all_checks(self):
        """Tüm testleri çalıştırır"""
        self.run_ping_test()
        self.get_ip_info()
        self.detect_web_tech()
        self.check_waf()
        self.check_cloudflare()
        self.whois_lookup()
        self.detect_technologies()
        self.analyze_headers()
        self.check_cms()
        self.check_javascript_frameworks()
        self.check_web_servers()
        self.check_analytics()
        self.check_cdn()
        return self.results

    def run_ping_test(self):
        """Ping testi yapar"""
        try:
            domain = urlparse(self.target).netloc
            response = subprocess.run(
                ['ping', '-c', '4', domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=setting.get('timeout', 10)
            )
            self.results['ping_test'] = {
                'status': 'success' if response.returncode == 0 else 'failed',
                'output': response.stdout.decode()
            }
        except Exception as e:
            self.results['ping_test'] = {'error': str(e)}

    def get_ip_info(self):
        """IP adresi ve DNS bilgilerini alır"""
        try:
            domain = urlparse(self.target).netloc
            ip_address = socket.gethostbyname(domain)
        
            dns_records = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(r) for r in answers]
                except:
                    pass
            
            self.results['ip_info'] = {
                'ip_address': ip_address,
                'dns_records': dns_records,
                'reverse_dns': socket.getfqdn(ip_address)
            }
        except Exception as e:
            self.results['ip_info'] = {'error': str(e)}

    def detect_web_tech(self):
        """Web sunucusu ve temel teknolojileri tespit eder"""
        try:
            response = requests.head(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10),
                allow_redirects=True
            )
            
            server_info = {
                'server': response.headers.get('Server', 'Unknown'),
                'x-powered-by': response.headers.get('X-Powered-By', 'Unknown'),
                'content-type': response.headers.get('Content-Type', 'Unknown')
            }
            
            server_info['cloudflare'] = 'cf-ray' in response.headers
            
            if self.target.startswith('https://'):
                domain = urlparse(self.target).netloc
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        server_info['ssl'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'expires': cert['notAfter'],
                            'subject': dict(x[0] for x in cert['subject'])
                        }
            
            self.results['server_info'] = server_info
            
        except Exception as e:
            self.results['server_info'] = {'error': str(e)}

    def detect_technologies(self):
        """Sayfa içeriğinden teknolojileri tespit eder"""
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10),
                allow_redirects=True
            )
            content = response.text.lower()
            soup = BeautifulSoup(content, 'html.parser')
            
            # Meta tag'lerden teknoloji bilgileri
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator:
                self.add_technology('Generator', meta_generator.get('content', ''))
            
            # Script ve linklerden teknoloji tespiti
            for script in soup.find_all('script'):
                src = script.get('src', '').lower()
                if 'jquery' in src:
                    self.add_technology('JavaScript', 'jQuery')
                if 'react' in src:
                    self.add_technology('JavaScript Framework', 'React')
                if 'vue' in src:
                    self.add_technology('JavaScript Framework', 'Vue.js')
                if 'angular' in src:
                    self.add_technology('JavaScript Framework', 'Angular')
            
            # CSS framework'leri
            for link in soup.find_all('link', attrs={'rel': 'stylesheet'}):
                href = link.get('href', '').lower()
                if 'bootstrap' in href:
                    self.add_technology('CSS Framework', 'Bootstrap')
                if 'foundation' in href:
                    self.add_technology('CSS Framework', 'Foundation')
                if 'materialize' in href:
                    self.add_technology('CSS Framework', 'Materialize')
            
            # HTML içindeki pattern'ler
            patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'media/system/js/', 'com_content'],
                'Drupal': ['drupal', 'sites/all/', 'core/assets'],
                'Laravel': ['/storage/', 'laravel'],
                'Django': ['csrfmiddlewaretoken', 'django']
            }
            
            for tech, sigs in patterns.items():
                if any(sig in content for sig in sigs):
                    self.add_technology('CMS/Framework', tech)
            
        except Exception as e:
            self.results['technologies'].append({'error': str(e)})

    def add_technology(self, category, name, confidence='high'):
        """Teknoloji ekler (eğer zaten eklenmemişse)"""
        tech_exists = any(t['name'] == name for t in self.results['technologies'])
        if not tech_exists:
            self.results['technologies'].append({
                'category': category,
                'name': name,
                'confidence': confidence
            })

    def check_waf(self):
        """WAF varlığını kontrol eder"""
        try:
            response = requests.get(
                self.target + "/'",
                headers=self.headers,
                timeout=setting.get('timeout', 5)
            )
            
            waf_detected = False
            waf_name = "Unknown"
            
            # WAF tespiti için çeşitli işaretler
            if response.status_code in [403, 406, 419]:
                waf_detected = True
                server_header = response.headers.get('Server', '').lower()
                
                if 'cloudflare' in server_header:
                    waf_name = "Cloudflare"
                elif 'akamai' in server_header:
                    waf_name = "Akamai"
                elif 'imperva' in server_header:
                    waf_name = "Imperva"
                elif 'barracuda' in server_header:
                    waf_name = "Barracuda"
                elif 'fortinet' in server_header:
                    waf_name = "Fortinet"
            
            self.results['waf'] = {
                'detected': waf_detected,
                'name': waf_name if waf_detected else None
            }
        except Exception as e:
            self.results['waf'] = {'error': str(e)}

    def check_cloudflare(self):
        """Cloudflare kullanıp kullanmadığını kontrol eder"""
        try:
            response = requests.head(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 5)
            )
            
            cloudflare = False
            if 'cf-ray' in response.headers:
                cloudflare = True
            if 'server' in response.headers and 'cloudflare' in response.headers['server'].lower():
                cloudflare = True
            
            self.results['cloudflare'] = cloudflare
        except Exception as e:
            self.results['cloudflare'] = {'error': str(e)}

    def whois_lookup(self):
        """WHOIS bilgilerini alır (basit versiyon)"""
        try:
            domain = urlparse(self.target).netloc
            if ':' in domain:  # Port numarasını kaldır
                domain = domain.split(':')[0]
            
            # Linux/macOS için whois komutu
            try:
                result = subprocess.run(
                    ['whois', domain],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=setting.get('timeout', 10)
                )
                self.results['whois'] = result.stdout.decode()
            except:
                # Windows için veya whois komutu yoksa alternatif
                import whois
                w = whois.whois(domain)
                self.results['whois'] = str(w)
        except Exception as e:
            self.results['whois'] = {'error': str(e)}

    def analyze_headers(self):
        """HTTP başlıklarını analiz eder"""
        try:
            response = requests.head(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 5)
            )
            
            headers_analysis = {}
            server_headers = ['Server', 'X-Powered-By', 'X-Generator']
            
            for header in server_headers:
                if header in response.headers:
                    headers_analysis[header.lower()] = response.headers[header]
            
            # Özel framework işaretleri
            if 'x-drupal-cache' in response.headers:
                self.add_technology('CMS', 'Drupal')
            if 'x-generator' in response.headers and 'drupal' in response.headers['x-generator'].lower():
                self.add_technology('CMS', 'Drupal')
            if 'x-aspnet-version' in response.headers:
                self.add_technology('Backend', 'ASP.NET')
            if 'x-aspnetmvc-version' in response.headers:
                self.add_technology('Backend', 'ASP.NET MVC')
            
            self.results['headers_analysis'] = headers_analysis
        except Exception as e:
            self.results['headers_analysis'] = {'error': str(e)}

    def check_cms(self):
        """CMS tespiti yapar"""
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10)
            )
            content = response.text.lower()
            
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'media/system/js/', 'com_content'],
                'Drupal': ['drupal', 'sites/all/', 'core/assets'],
                'Magento': ['magento', '/skin/frontend/'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'PrestaShop': ['prestashop', 'js/tools.js'],
                'OpenCart': ['opencart', 'catalog/view/theme'],
                'Laravel': ['/storage/', 'laravel'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'Ruby on Rails': ['rails', 'ruby']
            }
            
            detected_cms = None
            for cms, sigs in cms_signatures.items():
                if any(sig in content for sig in sigs):
                    detected_cms = cms
                    self.add_technology('CMS/Framework', cms)
                    break
            
            self.results['cms'] = detected_cms if detected_cms else 'Unknown'
        except Exception as e:
            self.results['cms'] = {'error': str(e)}

    def check_javascript_frameworks(self):
        """JavaScript framework'lerini tespit eder"""
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10)
            )
            content = response.text.lower()
            
            js_frameworks = {
                'React': ['react', 'react-dom'],
                'Vue.js': ['vue', 'vue.js'],
                'Angular': ['angular', 'ng-'],
                'jQuery': ['jquery'],
                'Backbone.js': ['backbone'],
                'Ember.js': ['ember'],
                'Meteor': ['meteor'],
                'Svelte': ['svelte']
            }
            
            detected_frameworks = []
            for framework, sigs in js_frameworks.items():
                if any(sig in content for sig in sigs):
                    detected_frameworks.append(framework)
                    self.add_technology('JavaScript Framework', framework)
            
            self.results['javascript_frameworks'] = detected_frameworks if detected_frameworks else 'None detected'
        except Exception as e:
            self.results['javascript_frameworks'] = {'error': str(e)}

    def check_web_servers(self):
        """Web sunucusu teknolojisini tespit eder"""
        try:
            response = requests.head(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 5)
            )
            
            server_header = response.headers.get('Server', '').lower()
            server = 'Unknown'
            
            if 'apache' in server_header:
                server = 'Apache'
            elif 'nginx' in server_header:
                server = 'Nginx'
            elif 'iis' in server_header:
                server = 'Microsoft IIS'
            elif 'lighttpd' in server_header:
                server = 'Lighttpd'
            elif 'cloudflare' in server_header:
                server = 'Cloudflare'
            
            self.results['web_server'] = server
            self.add_technology('Web Server', server)
        except Exception as e:
            self.results['web_server'] = {'error': str(e)}

    def check_analytics(self):
        """Analytics araçlarını tespit eder"""
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10)
            )
            content = response.text.lower()
            
            analytics_tools = {
                'Google Analytics': ['google-analytics.com/analytics.js', 'ga.js', 'gtag.js'],
                'Google Tag Manager': ['googletagmanager.com/gtm.js'],
                'Facebook Pixel': ['facebook.com/tr/', 'fbq('],
                'Hotjar': ['hotjar.com'],
                'Yandex Metrica': ['yandex.ru/metrika'],
                'Matomo (Piwik)': ['matomo', 'piwik.js']
            }
            
            detected_tools = []
            for tool, sigs in analytics_tools.items():
                if any(sig in content for sig in sigs):
                    detected_tools.append(tool)
                    self.add_technology('Analytics', tool)
            
            self.results['analytics_tools'] = detected_tools if detected_tools else 'None detected'
        except Exception as e:
            self.results['analytics_tools'] = {'error': str(e)}

    def check_cdn(self):
        """CDN kullanımını tespit eder"""
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                timeout=setting.get('timeout', 10)
            )
            content = response.text.lower()
            
            cdn_providers = {
                'Cloudflare': ['cloudflare'],
                'Akamai': ['akamai'],
                'Fastly': ['fastly'],
                'Amazon CloudFront': ['cloudfront.net'],
                'Azure CDN': ['azureedge.net'],
                'Google Cloud CDN': ['gstatic.com', 'googleusercontent.com']
            }
            
            detected_cdns = []
            for cdn, sigs in cdn_providers.items():
                if any(sig in content for sig in sigs):
                    detected_cdns.append(cdn)
                    self.add_technology('CDN', cdn)
            
            # Header'lardan CDN tespiti
            server_header = response.headers.get('Server', '').lower()
            if 'cloudflare' in server_header and 'Cloudflare' not in detected_cdns:
                detected_cdns.append('Cloudflare')
                self.add_technology('CDN', 'Cloudflare')
            
            self.results['cdn_providers'] = detected_cdns if detected_cdns else 'None detected'
        except Exception as e:
            self.results['cdn_providers'] = {'error': str(e)}

def print_banner():
    print(Fore.CYAN + r"""
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
    print(Fore.YELLOW + "[*] FunnelWS Web Vulnerability Scanner")
    print(Style.RESET_ALL)

def print_section(title, emoji, color=Fore.GREEN):
    print("\n" + color + f" {emoji} {title.upper()} {emoji} ")
    print(color + "═" * (len(title) + 4 + len(emoji)*2))

def print_tech(category, name, confidence="high"):
    emoji = ""
    if confidence == "high":
        emoji = "✅"
    elif confidence == "medium":
        emoji = "⚠️"
    else:
        emoji = "❓"
    
    print(f"{Fore.BLUE}{emoji} {Fore.CYAN}{category}: {Fore.WHITE}{name}")

def print_result(key, value, emoji="🔹"):
    print(f"{Fore.MAGENTA}{emoji} {Fore.YELLOW}{key}: {Fore.WHITE}{value}")

def print_detailed_info(results):
    print_section("Temel Bilgiler", "🌐", Fore.CYAN)
    print_result("Hedef", results['target'])
    print_result("Tarama Zamanı", results['timestamp'])
    print_result("IP Adresi", results['ip_info'].get('ip_address', 'Bilinmiyor'))
    
    print_section("Teknolojiler", "🔍", Fore.GREEN)
    if not results['technologies']:
        print(f"{Fore.RED}⛔ Hiçbir teknoloji tespit edilemedi")
    else:
        for tech in results['technologies']:
            print_tech(tech['category'], tech['name'], tech.get('confidence', 'high'))
    
    print_section("Detaylı Bilgiler", "📊", Fore.YELLOW)
    print_result("Web Sunucusu", results.get('web_server', 'Bilinmiyor'), "🖥️")
    print_result("CMS", results.get('cms', 'Bilinmiyor'), "📝")
    print_result("WAF", results['waf'].get('name', 'Tespit edilemedi'), "🛡️")
    print_result("Cloudflare", "Evet ✅" if results.get('cloudflare', False) else "Hayır ❌", "☁️")
    
    print_section("JavaScript Framework'ler", "⚛️", Fore.BLUE)
    js_frameworks = results.get('javascript_frameworks', 'Tespit edilemedi')
    if isinstance(js_frameworks, list):
        for framework in js_frameworks:
            print(f"{Fore.GREEN}  ➤ {Fore.WHITE}{framework}")
    else:
        print(f"{Fore.WHITE}  {js_frameworks}")
    
    print_section("Analiz Araçları", "📈", Fore.MAGENTA)
    analytics = results.get('analytics_tools', 'Tespit edilemedi')
    if isinstance(analytics, list):
        for tool in analytics:
            print(f"{Fore.GREEN}  ➤ {Fore.WHITE}{tool}")
    else:
        print(f"{Fore.WHITE}  {analytics}")
    
    print_section("CDN Sağlayıcılar", "🚀", Fore.CYAN)
    cdns = results.get('cdn_providers', 'Tespit edilemedi')
    if isinstance(cdns, list):
        for cdn in cdns:
            print(f"{Fore.GREEN}  ➤ {Fore.WHITE}{cdn}")
    else:
        print(f"{Fore.WHITE}  {cdns}")
    
    # DNS bilgilerini göster
    if 'dns_records' in results['ip_info'] and results['ip_info']['dns_records']:
        print_section("DNS Kayıtları", "🔗", Fore.GREEN)
        for record_type, records in results['ip_info']['dns_records'].items():
            print(f"{Fore.YELLOW}  {record_type}:")
            for record in records:
                print(f"    {Fore.WHITE}➤ {record}")
    
    print("\n" + Fore.GREEN + "✨ Tarama tamamlandı! ✨")

def main():
    domain = input(Fore.CYAN + "\n🔎 Hedef URL veya IP girin: " + Fore.WHITE).strip()
    scanner = WebTechScanner(domain)
    results = scanner.run_all_checks()
    
    print_banner()
    print_detailed_info(results)

if __name__ == "__main__":
    main()