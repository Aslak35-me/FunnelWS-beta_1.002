import requests
import socks
import socket
import dns.resolver
import time
import random
import subprocess
import ssl
from urllib.parse import urlparse
from config.useragent import get_random_useragent  # Artık doğrudan buradan çekiyoruz
import config.setting as setting


"""

# VERSİON 1.002

1 ping atma
2 user agent çalıştırma
3 tor çalıştırma 
4 ip bulma (shodan + daha gelişmiş bir yöntem sonra karşılaştırma)
5 dns taraması
6 waf taraması
7 firewall taraması
8 cloudflare testi
9 rate limit tester
10 whois bilgisi
11 nmap taraması

"""

domain = input("Enter target URL or IP: ").strip()

def run_ping_test(self):
    """Ping testi yapar"""
    try:
        domain = urlparse(self.target).netloc
        response = subprocess.run(
            ['ping', '-c', '4', domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout
        )
        self.results['ping_test'] = {
            'status': 'success' if response.returncode == 0 else 'failed',
            'output': response.stdout.decode()
        }
    except Exception as e:
        self.results['ping_test'] = {'error': str(e)}

def get_random_user_agent():
    return get_random_useragent()

def tor_request(url):
    proxies = {
        'http': 'socks5h://143.6.0.1:9050',
        'https': 'socks5h://134.5.2.0:8962'
    }

    headers = {
        "User-Agent": get_random_user_agent()
    }

    try:
        r = requests.get(url, proxies=proxies, headers=headers, timeout=10)
        return r.status_code
    except requests.exceptions.RequestException as e:
        print("Hata oluştu:", e)
        return None

def get_ip_info(target):
    """IP adresi ve DNS bilgilerini alır"""
    try:
        domain = urlparse(target).netloc
        ip_address = socket.gethostbyname(domain)
        dns_records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(r) for r in answers]
            except:
                pass
        
        result = {
            'ip_address': ip_address,
            'dns_records': dns_records,
            'reverse_dns': socket.getfqdn(ip_address)
        }
        return result
    except Exception as e:
        return {'error': str(e)}


def detect_web_tech(self):
    """Web sunucusu ve teknolojilerini tespit eder"""
    try:
        response = requests.head(
            self.target,
            headers=self.headers,
            timeout=self.timeout
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
        
        response = requests.get(
            self.target,
            headers=self.headers,
            timeout=self.timeout
        )
        content = response.text.lower()
        
        cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'media/system/js/', 'com_content'],
            'drupal': ['drupal', 'sites/all/', 'core/assets']
        }
        
        detected_cms = 'Unknown'
        for cms, sigs in cms_signatures.items():
            if any(sig in content for sig in sigs):
                detected_cms = cms.capitalize()
                break
        
        self.results['cms'] = detected_cms
        
    except Exception as e:
        self.results['server_info'] = {'error': str(e)}