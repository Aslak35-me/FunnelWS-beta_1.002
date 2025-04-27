#!/bin/bash
### şuanlık sadece mini birşey yapıldı ihtiyaçlara göre düzenlenecektir!
# Renk Tanımları
GREEN="\e[32m"
CYAN="\e[36m"
RESET="\e[0m"

echo -e "${CYAN}Sistem güncelleniyor...${RESET}"
sudo apt update && sudo apt upgrade -y

echo -e "${CYAN}Gerekli paketler yükleniyor...${RESET}"
sudo apt install -y python3 python3-pip git curl nmap sqlmap hydra whois nikto wapiti

echo -e "${CYAN}Python bağımlılıkları yükleniyor...${RESET}"
pip3 install colorama requests beautifulsoup4 selenium bs4 dnspython python-whois

echo -e "${CYAN}Ek güvenlik araçları yükleniyor...${RESET}"
# SQL Injection araçları
git clone https://github.com/sqlmapproject/sqlmap.git scanners/sql_injection/sqlmap-fast
git clone https://github.com/RedHawk-Development/RedHawk.git scanners/sql_injection/REDhawk

# XSS araçları
git clone https://github.com/s0md3v/XSStrike.git scanners/xss/XSStrike

# Diğer araçlar
git clone https://github.com/aboul3la/Sublist3r.git scanners/subdomain_takeover/sublist3r

echo -e "${CYAN}Requirements.txt dosyasındaki bağımlılıklar yükleniyor...${RESET}"
if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt
fi

echo -e "${CYAN}Dizin yapısı oluşturuluyor...${RESET}"
mkdir -p logs/sql_logs
mkdir -p scan_results
mkdir -p exploit-database/logs

echo -e "${GREEN}Kurulum tamamlandı!${RESET}"
echo -e "Çalıştırmak için: ${CYAN}python3 menu.py${RESET}"