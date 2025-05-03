import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import threading
import ftplib
import json
from config import useragent
from config import colorprint

# setting.json dosyasını oku
with open(os.path.join(os.path.dirname(__file__), 'config', 'setting.json'), 'r', encoding='utf-8') as f:
    setting = json.load(f)

### target alma sistemi yanlış düzeltilicek
PanelFound = []

def check_ftp_port(host):
    try:
        ftp = ftplib.FTP(host, timeout=setting.get('ftp_timeout', 3))
        ftp.quit()
        return True
    except ftplib.all_errors as e:
        return False

def panel_check(url, panels):
    global PanelFound
    durum = 0
    
    for panel in panels:
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if panel.find("{}"):
                domain = domain.replace("www.", "")
                panelcheck = panel.replace("{}", domain)
            else:
                panelcheck = panel.replace("{}", domain)
            if url.find("https://") > -1:
                panelcheck = "https://" + panelcheck
            else:
                panelcheck = "http://" + panelcheck
            user_agent = {'User-agent': useragent.get_useragent()}
            response = requests.get(panelcheck, headers=user_agent, timeout=setting.get('request_timeout', 10))
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                ftp_status = str(check_ftp_port(domain))
                colorprint.colorprint(f"{url} | {panelcheck} | {ftp_status}")
                PanelFound.append(f"{url} | {panelcheck} | {ftp_status}")
                durum = 1
                break
        except:       
            pass
    if durum == 0:
        ftp_status = str(check_ftp_port(domain))
        colorprint.colorprint(f"{url} | - | {ftp_status}")
        PanelFound.append(f"{url} | - | {ftp_status}")

def main(_type, thread=50):
    global PanelFound
    PanelFound = []
    try:
        with open("results/sql.txt", "r") as f:
            target = f.read().splitlines()
    except FileNotFoundError:
        colorprint.colorprint("SQL results file not found: results/sql.txt", "e")
        return
    
    if _type == 0:
        try:
            with open("files/panels.txt", "r") as f:
                panels = f.read().splitlines()
        except FileNotFoundError:
            colorprint.colorprint("Panels file not found: files/panels.txt", "e")
            return
    else:
        try:
            with open("files/quickpanel.txt", "r") as f:
                panels = f.read().splitlines()
        except FileNotFoundError:
            colorprint.colorprint("Quickpanel file not found: files/quickpanel.txt", "e")
            return

    threads = []
    i = 0
    while i < len(target):
        for j in range(i, min(i + thread, len(target))):
            try:
                t = threading.Thread(target=panel_check, args=(target[j], panels))
                threads.append(t)
                t.start()
            except:
                pass
        for t in threads:
            t.join()
        i += thread
        threads = []
    
    os.makedirs("results", exist_ok=True)
    with open("results/results_panels.txt", "w") as file:
        file.writelines("%s\n" % url for url in PanelFound)
    colorprint.colorprint("results/results_panels.txt kaydedildi!")