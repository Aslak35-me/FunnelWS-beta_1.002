import requests
import time
import socket
import random
import string
import threading
import json
import difflib
import statistics
import dns.resolver
import stem.process
from stem import Signal
from stem.control import Controller
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import re
from colorama import init, Fore, Back, Style
import sys
from pathlib import Path
import json

def ön_target_verme():
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

    # 4. Ayarlardan değerleri al
    TARGET_FILE_PATH = setting.get("TARGET_FILE_PATH")
    TARGET = setting.get("TARGET")
    TARGET_FILE_CHECK = setting.get("TARGET_FILE_CHECK")

class HoneypotDetector:
    def __init__(self, target_url, proxy=None, user_agent=None, threads=10, tor_rotation=False):
        self.target_url = self.normalize_url(target_url)
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
        self.headers = {'User-Agent': user_agent or self.generate_random_ua()}
        self.threads = threads
        self.tor_rotation = tor_rotation
        self.tor_process = None
        self.session = requests.Session()
        self.session.proxies = self.proxies
        self.session.headers.update(self.headers)
        
        # Load honeypot signatures from file
        self.known_honeypot_signatures = self.load_signatures('honeypot_signatures.json')
        
        # Initialize results structure
        self.results = {
            'target': self.target_url,
            'tests': {
                'fingerprint': {},
                'behavioral': {},
                'timing': {},
                'session': {},
                'subdomains': [],
                'block_detection': False,
                'similarity_analysis': {}
            },
            'honeypot_probability': 0,
            'verdict': 'Unknown'
        }
        
        # Initialize payloads
        self.payloads = {
            'sqli': ["' OR '1'='1' --", "' UNION SELECT null, version() --", 
                     "'; DROP TABLE users --", "' OR SLEEP(5) --"],
            'xss': ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(document.cookie)>", "<body onload=prompt(1)>"]
        }
        
        # Start Tor if needed
        if tor_rotation:
            self.start_tor()

    def normalize_url(self, url):
        """Ensure URL has a scheme"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def start_tor(self):
        """Start Tor process for IP rotation"""
        try:
            self.tor_process = stem.process.launch_tor_with_config(
                config = {
                    'SocksPort': '9050',
                    'ControlPort': '9051',
                    'CookieAuthentication': '1',
                },
                init_msg_handler = lambda line: print(line) if "Bootstrapped" in line else None,
            )
            self.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            self.session.proxies = self.proxies
            print(Fore.GREEN + "[+] Tor started successfully")
        except Exception as e:
            print(Fore.RED + f"[-] Tor start failed: {e}")
            self.tor_rotation = False

    def rotate_tor_ip(self):
        """Rotate Tor IP address"""
        if not self.tor_rotation:
            return
            
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            print(Fore.GREEN + "[+] Tor IP rotated")
        except Exception as e:
            print(Fore.RED + f"[-] Tor IP rotation failed: {e}")

    def generate_random_ua(self):
        """Generate random user agent"""
        browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
        ]
        return random.choice(browsers)

    def random_payload(self, base_payload):
        """Randomize payload to avoid detection"""
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        return base_payload.replace("alert(1)", f"alert({random_str})").replace("OR '1'", f"OR '{random_str}'")

    def load_signatures(self, filename):
        """Load honeypot signatures from JSON file"""
        default_signatures = {
            "server_headers": ["Honeypot", "Dionaea", "Kippo", "Cowrie", "T-Pot", "Glastopf", "Conpot", "Honeytrap"],
            "page_content": ["honeypot", "decoy", "trap", "dummy server", "flag", "token", "admin console"],
            "response_codes": [200, 403, 302, 401],
            "ports": [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5900, 8080]
        }
        
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except:
            return default_signatures

    def send_request(self, url, method='GET', payload=None, cookies=None, retries=3):
        """Send HTTP request with random delays and retry logic"""
        start_time = time.time()
        
        # Add random delay to avoid detection
        time.sleep(random.uniform(0.5, 2.0))
        
        for attempt in range(retries):
            try:
                if method == 'GET':
                    response = self.session.get(url, params=payload, cookies=cookies, timeout=10)
                elif method == 'POST':
                    response = self.session.post(url, data=payload, cookies=cookies, timeout=10)
                else:
                    return None, 0
                
                response_time = time.time() - start_time
                return response, response_time
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(random.uniform(1, 3))
                    continue
                return None, 0

    def passive_subdomain_lookup(self, domain):
        """Find subdomains using crt.sh certificate database"""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subdomains = set()
        
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value'].lower()
                    if '\n' in name:
                        for sub in name.split('\n'):
                            subdomains.add(sub)
                    else:
                        subdomains.add(name)
        except Exception as e:
            print(Fore.RED + f"[!] crt.sh error: {e}")
        
        return list(subdomains)

    def active_subdomain_check(self, subdomain):
        """Check if subdomain is active via DNS and HTTP"""
        try:
            # DNS resolution
            answers = dns.resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # HTTP check
            for scheme in ['http', 'https']:
                url = f"{scheme}://{subdomain}"
                response, _ = self.send_request(url)
                if response and response.status_code < 400:
                    return subdomain, ips, url, response.status_code
        except:
            pass
        
        return None

    def fingerprint_analysis(self):
        """Enhanced fingerprint detection"""
        response, _ = self.send_request(self.target_url)
        if not response:
            return
        
        # 1. Header Analysis
        headers_to_check = ['Server', 'X-Powered-By', 'Set-Cookie', 'X-AspNet-Version', 'Via']
        self.results['tests']['fingerprint']['headers'] = {}
        
        for header in headers_to_check:
            if header in response.headers:
                header_value = response.headers[header]
                self.results['tests']['fingerprint']['headers'][header] = header_value
                
                # Check against known honeypot signatures
                for signature in self.known_honeypot_signatures['server_headers']:
                    if signature.lower() in header_value.lower():
                        self.results['tests']['fingerprint']['known_signature'] = signature
                        self.results['honeypot_probability'] += 20
        
        # 2. Content Analysis
        content = response.text.lower()
        self.results['tests']['fingerprint']['content_length'] = len(response.content)
        
        for keyword in self.known_honeypot_signatures['page_content']:
            if keyword in content:
                self.results['tests']['fingerprint']['content_keyword'] = keyword
                self.results['honeypot_probability'] += 15
        
        # 3. Fake URL Test
        fake_url = urljoin(self.target_url, f"fake_page_{random.randint(1000,9999)}.html")
        fake_response, _ = self.send_request(fake_url)
        
        if fake_response:
            similarity = difflib.SequenceMatcher(
                None, response.text, fake_response.text).ratio()
            
            if similarity > 0.95:
                self.results['tests']['fingerprint']['identical_fake_response'] = True
                self.results['tests']['fingerprint']['similarity_score'] = similarity
                self.results['honeypot_probability'] += 25

    def behavioral_analysis(self):
        """Advanced behavioral detection with payload randomization"""
        # 1. Non-existing URL test
        fake_url = urljoin(self.target_url, f"non_existing_{random.randint(10000,99999)}.html")
        fake_response, _ = self.send_request(fake_url)
        
        if fake_response and fake_response.status_code == 200:
            self.results['tests']['behavioral']['fake_url_200'] = True
            self.results['honeypot_probability'] += 10
        
        # 2. Payload response time test
        test_url = urljoin(self.target_url, "search?query=")
        payload_times = {'sqli': [], 'xss': []}
        
        for payload_type in self.payloads:
            for payload in self.payloads[payload_type]:
                randomized_payload = self.random_payload(payload)
                _, response_time = self.send_request(test_url + randomized_payload)
                payload_times[payload_type].append(response_time)
                
                if response_time < 0.1:  # Unnaturally fast response
                    self.results['tests']['behavioral'][f'fast_{payload_type}'] = response_time
                    self.results['honeypot_probability'] += 5
        
        # 3. Rate limiting detection
        start_time = time.time()
        for i in range(10):
            self.send_request(self.target_url)
            if i == 5 and self.tor_rotation:
                self.rotate_tor_ip()
        total_time = time.time() - start_time
        
        if total_time > 15:  # Unusual delay
            self.results['tests']['behavioral']['rate_limiting'] = total_time
            self.results['honeypot_probability'] += 10

    def timing_analysis(self):
        """Statistical timing analysis"""
        tests = {
            'normal': self.target_url,
            'empty': urljoin(self.target_url, f"empty_{random.randint(1000,9999)}.html"),
            'malicious': urljoin(self.target_url, f"search?query=' OR 1=1 --")
        }
        
        times = {name: [] for name in tests}
        
        # Collect multiple samples
        for name, url in tests.items():
            for _ in range(5):
                _, response_time = self.send_request(url)
                times[name].append(response_time)
                time.sleep(random.uniform(0.5, 1.5))
        
        # Calculate statistics
        stats = {}
        for name, values in times.items():
            if values:
                stats[name] = {
                    'mean': statistics.mean(values),
                    'stdev': statistics.stdev(values) if len(values) > 1 else 0
                }
        
        self.results['tests']['timing'] = stats
        
        # Check for significant delays
        if (stats.get('malicious') and stats.get('normal') and 
            stats['malicious']['mean'] > stats['normal']['mean'] * 3):
            self.results['tests']['timing']['suspicious_delay'] = True
            self.results['honeypot_probability'] += 15

    def session_tracking_test(self):
        """Enhanced session behavior analysis"""
        # First request without cookies
        response1, _ = self.send_request(self.target_url)
        initial_cookies = response1.cookies
        
        # Second request with same cookies but different UA
        new_headers = self.headers.copy()
        new_headers['User-Agent'] = self.generate_random_ua()
        self.session.headers.update(new_headers)
        response2, _ = self.send_request(self.target_url, cookies=initial_cookies)
        
        # Third request without cookies
        self.session.headers.update({'User-Agent': self.generate_random_ua()})
        response3, _ = self.send_request(self.target_url, cookies=None)
        
        # Session consistency check
        if (not initial_cookies and 
            response2.cookies and 
            response3.cookies and
            response2.cookies == response3.cookies):
            self.results['tests']['session']['inconsistent_session'] = True
            self.results['honeypot_probability'] += 10
        
        # Cookie entropy analysis
        if response1.cookies:
            for name, value in response1.cookies.items():
                if self.is_high_entropy(value):
                    self.results['tests']['session']['high_entropy_cookie'] = name
                    self.results['honeypot_probability'] += 5

    def is_high_entropy(self, value):
        """Check if value has high entropy (possible hash/token)"""
        if len(value) < 20:
            return False
            
        # Check for base64 pattern
        if re.match(r'^[a-zA-Z0-9+/]+={0,2}$', value):
            return True
            
        # Check for hex pattern
        if re.match(r'^[a-fA-F0-9]{32,}$', value):
            return True
            
        return False

    def subdomain_scan(self):
        """Comprehensive subdomain discovery"""
        domain = urlparse(self.target_url).netloc
        base_domain = ".".join(domain.split('.')[-2:])
        
        # Passive discovery (crt.sh)
        passive_subs = self.passive_subdomain_lookup(base_domain)
        active_subs = []
        
        # Active discovery
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.active_subdomain_check, sub) for sub in passive_subs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ips, url, status = result
                    active_subs.append({
                        'subdomain': subdomain,
                        'ips': ips,
                        'url': url,
                        'status': status
                    })
        
        self.results['tests']['subdomains'] = active_subs
        
        # Check for honeypot ports
        for sub in active_subs:
            for ip in sub['ips']:
                for port in self.known_honeypot_signatures['ports']:
                    if self.check_port_open(ip, port):
                        self.results['tests']['subdomains'].append({
                            'type': 'open_port',
                            'ip': ip,
                            'port': port
                        })
                        self.results['honeypot_probability'] += 5

    def check_port_open(self, ip, port, timeout=1):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def block_detection_test(self):
        """Advanced block detection"""
        test_urls = [
            self.target_url,
            urljoin(self.target_url, "admin"),
            urljoin(self.target_url, "wp-login.php")
        ]
        
        for i, url in enumerate(test_urls):
            response, _ = self.send_request(url)
            
            if response and response.status_code in [403, 429, 503]:
                self.results['tests']['block_detection'] = True
                self.results['honeypot_probability'] += 10
                break
            
            # Rotate IP after every 2nd request if Tor enabled
            if self.tor_rotation and i % 2 == 1:
                self.rotate_tor_ip()

    def similarity_analysis(self):
        """Compare responses to known honeypot patterns"""
        test_urls = [
            self.target_url,
            urljoin(self.target_url, "login"),
            urljoin(self.target_url, "admin")
        ]
        
        responses = []
        for url in test_urls:
            response, _ = self.send_request(url)
            if response:
                responses.append(response.text)
        
        if len(responses) < 2:
            return
        
        # Compare all response pairs
        similarities = []
        for i in range(len(responses)):
            for j in range(i+1, len(responses)):
                ratio = difflib.SequenceMatcher(None, responses[i], responses[j]).ratio()
                similarities.append(ratio)
        
        avg_similarity = statistics.mean(similarities) if similarities else 0
        self.results['tests']['similarity_analysis']['average'] = avg_similarity
        
        if avg_similarity > 0.85:
            self.results['tests']['similarity_analysis']['high_similarity'] = True
            self.results['honeypot_probability'] += 15

    def run_all_tests(self):
        """Execute all detection tests with threading"""
        tests = [
            self.fingerprint_analysis,
            self.behavioral_analysis,
            self.timing_analysis,
            self.session_tracking_test,
            self.subdomain_scan,
            self.block_detection_test,
            self.similarity_analysis
        ]
        
        with ThreadPoolExecutor(max_workers=min(len(tests), self.threads)) as executor:
            futures = [executor.submit(test) for test in tests]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    print(Fore.RED + f"Test error: {str(e)}")
        
        # Determine final verdict
        self.results['honeypot_probability'] = min(self.results['honeypot_probability'], 100)
        
        if self.results['honeypot_probability'] > 70:
            self.results['verdict'] = "High Probability Honeypot"
        elif self.results['honeypot_probability'] > 40:
            self.results['verdict'] = "Possible Honeypot"
        else:
            self.results['verdict'] = "Likely Not a Honeypot"
    
    def generate_report(self, format='json'):
        """Generate JSON/HTML Report"""
        if format == 'json':
            return json.dumps(self.results, indent=4)
        elif format == 'html':
            return self.generate_html_report()
    
    def generate_html_report(self):
        """Generate detailed HTML report"""
        soup = BeautifulSoup(features='html.parser')
        html = soup.new_tag('html')
        head = soup.new_tag('head')
        body = soup.new_tag('body')
        
        # Style
        style = soup.new_tag('style')
        style.string = """
            body { font-family: Arial, sans-serif; line-height: 1.6; }
            .container { width: 80%; margin: auto; }
            .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
            .positive { color: #d9534f; font-weight: bold; }
            .negative { color: #5cb85c; }
            .verdict { font-size: 1.5em; padding: 15px; text-align: center; margin: 20px 0; }
            table { width: 100%; border-collapse: collapse; margin: 15px 0; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .probability-bar { height: 30px; background: #eee; width: 100%; margin: 10px 0; }
            .probability-fill { height: 100%; background: #d9534f; }
        """
        head.append(style)
        title = soup.new_tag('title')
        title.string = f"Honeypot Report: {self.target_url}"
        head.append(title)
        
        # Body content
        container = soup.new_tag('div', **{'class': 'container'})
        
        # Header
        header = soup.new_tag('div', **{'class': 'header'})
        h1 = soup.new_tag('h1')
        h1.string = f"Honeypot Detection Report: {self.target_url}"
        header.append(h1)
        
        # Verdict
        verdict_div = soup.new_tag('div', **{'class': 'verdict'})
        verdict_text = soup.new_tag('h2')
        verdict_text.string = f"Verdict: {self.results['verdict']}"
        verdict_div.append(verdict_text)
        
        # Probability bar
        prob_div = soup.new_tag('div', **{'class': 'probability-bar'})
        fill_width = min(self.results['honeypot_probability'], 100)
        fill = soup.new_tag('div', **{
            'class': 'probability-fill',
            'style': f'width: {fill_width}%;'
        })
        prob_div.append(fill)
        
        # Probability text
        prob_text = soup.new_tag('p')
        prob_text.string = f"Honeypot Probability: {self.results['honeypot_probability']}%"
        verdict_div.append(prob_text)
        verdict_div.append(prob_div)
        container.append(verdict_div)
        
        # Detailed results
        for section, data in self.results['tests'].items():
            section_div = soup.new_tag('div', **{'class': 'section'})
            h2 = soup.new_tag('h2')
            h2.string = section.capitalize() + " Analysis"
            section_div.append(h2)
            
            if isinstance(data, dict):
                table = soup.new_tag('table')
                thead = soup.new_tag('thead')
                tbody = soup.new_tag('tbody')
                
                # Table headers
                tr_head = soup.new_tag('tr')
                th1 = soup.new_tag('th')
                th1.string = "Test"
                th2 = soup.new_tag('th')
                th2.string = "Result"
                tr_head.append(th1)
                tr_head.append(th2)
                thead.append(tr_head)
                
                # Table rows
                for key, value in data.items():
                    tr = soup.new_tag('tr')
                    td1 = soup.new_tag('td')
                    td1.string = key
                    td2 = soup.new_tag('td')
                    
                    if isinstance(value, dict):
                        td2.string = json.dumps(value, indent=2)
                    elif isinstance(value, list):
                        td2.string = ", ".join(map(str, value))
                    else:
                        td2.string = str(value)
                    
                    tr.append(td1)
                    tr.append(td2)
                    tbody.append(tr)
                
                table.append(thead)
                table.append(tbody)
                section_div.append(table)
            elif isinstance(data, list):
                ul = soup.new_tag('ul')
                for item in data:
                    li = soup.new_tag('li')
                    li.string = str(item)
                    ul.append(li)
                section_div.append(ul)
            else:
                p = soup.new_tag('p')
                p.string = str(data)
                section_div.append(p)
            
            container.append(section_div)
        
        body.append(container)
        html.append(head)
        html.append(body)
        soup.append(html)
        
        return soup.prettify()

    def __del__(self):
        """Cleanup Tor process"""
        if self.tor_process:
            self.tor_process.terminate()

# Kullanım Örneği
if __name__ == "__main__":
    ön_target_verme()
    target = TARGET
    
    detector = HoneypotDetector(
        target_url=target,
        tor_rotation=True,  # Tor IP rotasyonunu etkinleştir
        threads=20
    )
    
    print(Fore.CYAN + f"Tarama başlatılıyor: {target}")
    detector.run_all_tests()
    
    # JSON Rapor
    json_report = detector.generate_report('json')
    with open('report.json', 'w') as f:
        f.write(json_report)
    
    # HTML Rapor
    html_report = detector.generate_report('html')
    with open('report.html', 'w') as f:
        f.write(html_report)
    
    print(Fore.CYAN + "Tarama tamamlandı!")
    print(Fore.CYAN + f"Sonuç: {detector.results['verdict']}")
    print(Fore.CYAN + f"Olasılık: {detector.results['honeypot_probability']}%")
    print(Fore.CYAN + "Raporlar report.json ve report.html olarak kaydedildi.")