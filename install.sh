#!/bin/bash

# Renk Tanımları
GREEN="\e[32m"
CYAN="\e[36m"
RESET="\e[0m"

# Sistem tespiti ve kurulum işlemleri
platform=$(uname)

echo -e "${CYAN}Platform tespiti yapılıyor...${RESET}"
if [[ "$platform" == "Linux" ]]; then
    # Linux İçin İşlemler
    echo -e "${CYAN}Linux sistemi tespit edildi. Sistem güncelleniyor...${RESET}"
    sudo apt update && sudo apt upgrade -y

    echo -e "${CYAN}Gerekli paketler yükleniyor...${RESET}"
    sudo apt install -y python3 python3-pip git curl nmap sqlmap hydra whois nikto wapiti

    echo -e "${CYAN}Python bağımlılıkları yükleniyor...${RESET}"
    pip3 install colorama requests beautifulsoup4 selenium bs4 dnspython python-whois
    pip install selenium
    pip install webdriver-manager


    echo -e "${CYAN}Güvenlik araçları indiriliyor...${RESET}"
    # Araçları GitHub'dan klonla
    git clone https://github.com/sqlmapproject/sqlmap.git scanners/sql_injection/sqlmap
    git clone https://github.com/OWASP/ZAP-ROXY.git scanners/zaproxy
    git clone https://github.com/wpscanteam/wpscan.git scanners/wpscan
    git clone https://github.com/novm/nikto.git scanners/nikto
    git clone https://github.com/rapid7/metasploit-framework.git scanners/metasploit

    echo -e "${CYAN}Dizin yapısı oluşturuluyor...${RESET}"
    mkdir -p logs/sql_logs
    mkdir -p scan_results
    mkdir -p exploit-database/logs

    echo -e "${GREEN}Kurulum tamamlandı!${RESET}"
    echo -e "Çalıştırmak için: ${CYAN}python3 main.py${RESET}"

elif [[ "$platform" == "Darwin" ]]; then
    # macOS İçin İşlemler
    echo -e "${CYAN}macOS sistemi tespit edildi. Homebrew kullanılarak gerekli araçlar kuruluyor...${RESET}"

    # Homebrew kurulumu ve güncelleme
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    brew update && brew upgrade

    echo -e "${CYAN}Gerekli paketler yükleniyor...${RESET}"
    brew install python3 git curl nmap sqlmap hydra whois nikto wapiti

    echo -e "${CYAN}Python bağımlılıkları yükleniyor...${RESET}"
    pip3 install colorama requests beautifulsoup4 selenium bs4 dnspython python-whois
    pip install selenium
    pip install webdriver-manager


    echo -e "${CYAN}Güvenlik araçları indiriliyor...${RESET}"
    # Araçları GitHub'dan klonla
    git clone https://github.com/sqlmapproject/sqlmap.git scanners/sql_injection/sqlmap
    git clone https://github.com/OWASP/ZAP-ROXY.git scanners/zaproxy
    git clone https://github.com/wpscanteam/wpscan.git scanners/wpscan
    git clone https://github.com/novm/nikto.git scanners/nikto
    git clone https://github.com/rapid7/metasploit-framework.git scanners/metasploit

    echo -e "${CYAN}Dizin yapısı oluşturuluyor...${RESET}"
    mkdir -p logs/sql_logs
    mkdir -p scan_results
    mkdir -p exploit-database/logs

    echo -e "${GREEN}Kurulum tamamlandı!${RESET}"
    echo -e "Çalıştırmak için: ${CYAN}python3 main.py${RESET}"

else
    echo -e "${RED}Bu platform desteklenmiyor.${RESET}"
    exit 1
fi
