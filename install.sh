#!/bin/bash

# Renk Tanımları
GREEN="\e[32m"
CYAN="\e[36m"
RESET="\e[0m"

# Sistem tespiti ve kurulum işlemleri
platform=$(uname)
    echo -e "${CYAN}======================================${RESET}"
echo -e "${CYAN}Platform tespiti yapılıyor...${RESET}"
    echo -e "${CYAN}======================================${RESET}"
if [[ "$platform" == "Linux" ]]; then
    # Linux İçin İşlemler
    echo -e "${CYAN}=======================================================${RESET}"
    echo -e "${CYAN}Linux sistemi tespit edildi. Sistem güncelleniyor...${RESET}"
    echo -e "${CYAN}=======================================================${RESET}"
    sudo apt update && sudo apt upgrade -y
    sudo apt update
    sudo apt install golang-go -y
    sudo apt install python3 python3-pip -y
    if ! grep -q 'export PATH=$PATH:$(go env GOPATH)/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
    echo "[+] PATH güncellendi."
    else
    echo "[=] PATH zaten ayarlanmış."
    fi
    echo -e "${CYAN}===============================${RESET}"
    echo -e "${CYAN}Gerekli paketler yükleniyor...${RESET}"
    echo -e "${CYAN}===============================${RESET}"
    sudo apt install -y python3 python3-pip git curl nmap sqlmap hydra whois nikto wapiti

    echo -e "${CYAN}=====================================${RESET}"
    echo -e "${CYAN}Python bağımlılıkları yükleniyor...${RESET}"
    echo -e "${CYAN}=====================================${RESET}"
    pip3 install colorama requests beautifulsoup4 selenium bs4 dnspython python-whois
    pip install selenium
    pip install webdriver-manager
    
    # requirements.txt üzerinden kütüphanelerin kurulumu
    echo "[+] Gereken Python kütüphaneleri yükleniyor..."
    pip install -r requirements.txt
    
    echo -e "${CYAN}======================================${RESET}"
    echo -e "${CYAN}Güvenlik araçları indiriliyor...${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    # Araçları GitHub'dan klonla
    git clone https://github.com/sqlmapproject/sqlmap.git scanners/sql_injection/sqlmap
    git clone https://github.com/OWASP/ZAP-ROXY.git scanners/zaproxy
    git clone https://github.com/wpscanteam/wpscan.git scanners/wpscan
    git clone https://github.com/novm/nikto.git scanners/nikto
    git clone https://github.com/rapid7/metasploit-framework.git scanners/metasploit
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/OWASP/Amass/v3/...@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/gf@latest
    go install github.com/hakluke/hakrawler@latest
    go install github.com/tomnomnom/qsreplace@latest
    pip install dirsearch nuclei getJS anew

    echo -e "${CYAN}======================================${RESET}"
    echo -e "${CYAN}Dizin yapısı oluşturuluyor...${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    mkdir -p logs/sql_logs
    mkdir -p scan_results
    mkdir -p exploit-database/logs

    echo -e "${CYAN}======================================${RESET}"
    echo -e "${GREEN}Kurulum tamamlandı!${RESET}"
    echo -e "${CYAN}======================================${RESET}"
    echo -e "Çalıştırmak için: ${CYAN}python3 main.py${RESET}"

else
    echo -e "${RED}Bu platform desteklenmiyor.${RESET}"
    exit 1
fi
