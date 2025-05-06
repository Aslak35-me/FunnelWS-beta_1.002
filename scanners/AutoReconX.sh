#!/bin/bash

set -e

# Renkli çıktılar
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Araç dizinleri
TOOLS_DIR="$HOME/.autoreconx_tools"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"

# PATH güncelleme
update_path() {
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo -e "${YELLOW}[+] PATH güncelleniyor...${NC}"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.zshrc"
        export PATH="$PATH:$BIN_DIR"
    fi
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo "export PATH=\"\$PATH:$HOME/go/bin\"" >> "$HOME/.bashrc"
        echo "export PATH=\"\$PATH:$HOME/go/bin\"" >> "$HOME/.zshrc"
        export PATH="$PATH:$HOME/go/bin"
    fi
}

# Go kurulumu (en yeni sürüm)
install_go() {
    if ! command -v go &> /dev/null || [[ $(go version | awk '{print $3}' | sed 's/go//') < "1.21" ]]; then
        echo -e "${BLUE}[*] Go 1.21+ kurulumu...${NC}"
        sudo rm -rf /usr/local/go
        latest_go=$(curl -s https://go.dev/VERSION?m=text)
        wget "https://go.dev/dl/${latest_go}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo "export PATH=\$PATH:/usr/local/go/bin" >> "$HOME/.bashrc"
        echo "export PATH=\$PATH:/usr/local/go/bin" >> "$HOME/.zshrc"
        export PATH=$PATH:/usr/local/go/bin
        echo -e "${GREEN}[+] Go $latest_go kuruldu${NC}"
    fi
}

# Python kurulumu
install_python() {
    if ! command -v python3 &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${BLUE}[*] Python/pip kurulumu...${NC}"
        sudo apt update && sudo apt install -y python3 python3-pip python3-venv
        echo -e "${GREEN}[+] Python kuruldu${NC}"
    fi
}

# Go araç kurulumu (mod desteği ile)
install_go_tool() {
    local tool=$1
    local pkg=$2
    
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${BLUE}[*] $tool kurulumu...${NC}"
        GO111MODULE=on go install "$pkg@latest"
        echo -e "${GREEN}[+] $tool kuruldu${NC}"
    else
        echo -e "${YELLOW}[+] $tool zaten yüklü${NC}"
    fi
}

# Ana kurulum fonksiyonu
install_dependencies() {
    # Sistem bağımlılıkları
    echo -e "${BLUE}[*] Sistem bağımlılıkları kontrol ediliyor...${NC}"
    sudo apt update && sudo apt install -y git wget build-essential libssl-dev zlib1g-dev

    # Go kurulum
    install_go
    update_path

    # Python kurulum
    install_python

    # Go araçları
    declare -A go_tools=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        ["amass"]="github.com/owasp-amass/amass/v3/..."
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
        ["gau"]="github.com/lc/gau/v2/cmd/gau"
        ["getJS"]="github.com/003random/getJS"
        ["gf"]="github.com/tomnomnom/gf"
        ["qsreplace"]="github.com/tomnomnom/qsreplace"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    )

    for tool in "${!go_tools[@]}"; do
        install_go_tool "$tool" "${go_tools[$tool]}"
    done

    # Python araçları
    echo -e "${BLUE}[*] dirsearch kurulumu...${NC}"
    pip3 install --user dirsearch

    # Sistem araçları
    echo -e "${BLUE}[*] jq kurulumu...${NC}"
    sudo apt install -y jq

    # GF patternleri
    if [ ! -d "$HOME/.gf" ]; then
        echo -e "${BLUE}[*] GF patternleri indiriliyor...${NC}"
        mkdir -p "$HOME/.gf"
        git clone https://github.com/tomnomnom/gf "$TOOLS_DIR/gf"
        cp -r "$TOOLS_DIR/gf/examples" "$HOME/.gf/"
    fi

    # Go modülleri temizleme
    go clean -modcache
}

# Kurulumu başlat
install_dependencies

echo -e "${GREEN}[✔] Tüm bağımlılıklar başarıyla kuruldu!${NC}"

# Ana script devamı...
CONFIG_PATH="$(dirname "$0")/../config/setting.json"
OUTER_DIR="results"
WORDLIST="${WORDLIST:-~/SecLists/Discovery/Web-Content/raft-medium-words.txt}"

# JSON config'ini oku
if [ ! -f "$CONFIG_PATH" ]; then
    echo -e "${RED}[!] Hata: Config dosyası bulunamadı: $CONFIG_PATH${NC}"
    exit 1
fi

# JSON config'ini oku
TARGET_FILE_CHECK=$(jq -r '.TARGET_FILE_CHECK' "$CONFIG_PATH")
TARGET=$(jq -r '.TARGET' "$CONFIG_PATH")
TARGET_FILE_PATH=$(jq -r '.TARGET_FILE_PATH' "$CONFIG_PATH")

# Hedef listesi oluştur
targets=()

if [[ "$TARGET_FILE_CHECK" == "on" ]]; then
    echo -e "${YELLOW}[*] Hedefler dosyadan okunuyor: $TARGET_FILE_PATH${NC}"
    while IFS= read -r line; do
        cleaned=$(echo "$line" | xargs)
        if [[ -n "$cleaned" ]]; then
            targets+=("$cleaned")
        fi
    done < "$TARGET_FILE_PATH"
else
    echo -e "${YELLOW}[*] Tek hedef kullanılacak: $TARGET${NC}"
    targets+=("$TARGET")
fi

# Geliştirilmiş site kontrol fonksiyonu
check_site_availability() {
    local target=$1
    local host=$(echo "$target" | sed -E 's#(https?://)?([^:/]+).*#\2#')
    local success=false
    
    echo -e "${YELLOW}[*] Kontrol ediliyor: $target${NC}"
    
    # 1. Ping kontrolü (3 deneme, 2 saniye timeout)
    if ping -c 3 -W 2 "$host" &>/dev/null; then
        echo -e "${GREEN}[+] Ping başarılı: $host${NC}"
        success=true
    else
        echo -e "${RED}[-] Ping başarısız: $host${NC}"
    fi
    
    # 2. HTTP/HTTPS erişim kontrolü (curl ile)
    http_code=$(curl --max-time 10 -k -s -I -o /dev/null -w "%{http_code}" "$target" || true)
    
    if [[ "$http_code" =~ ^[23] ]]; then
        echo -e "${GREEN}[+] HTTP erişimi başarılı: $target (Status: $http_code)${NC}"
        success=true
    else
        echo -e "${RED}[-] HTTP erişimi başarısız: $target (Status: ${http_code:-"Connection failed"})${NC}"
    fi
    
    # Ping veya HTTP başarılıysa true döndür
    if $success; then
        return 0
    else
        return 1
    fi
}

# Aktif hedefleri kontrol et
active_targets=()
mkdir -p "$OUTER_DIR/logs"

echo -e "${YELLOW}[*] Canlı hedefler kontrol ediliyor...${NC}"
for target in "${targets[@]}"; do
    # Eğer http:// veya https:// yoksa ekle
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="http://$target"
    fi
    
    if check_site_availability "$target"; then
        active_targets+=("$target")
    else
        echo -e "${YELLOW}[!] Uyarı: $target için bazı kontroller başarısız oldu, ancak taramaya devam edilecek${NC}"
        active_targets+=("$target")
    fi
done

# Hiçbir hedef yoksa çık
if [ ${#active_targets[@]} -eq 0 ]; then
    echo -e "${RED}[!] Hiçbir hedef bulunamadı. Çıkılıyor.${NC}"
    exit 1
fi

# Tüm hedefler için tarama başlat (aktif olmayanlar dahil)
for target in "${active_targets[@]}"; do
    domain=$(echo "$target" | sed -E 's#https?://([^:/]+).*#\1#')
    outdir="$OUTER_DIR/$domain"
    mkdir -p "$outdir"

    echo -e "${YELLOW}🔎 $target için tarama başlatılıyor...${NC}"

    ## Subdomain tarama
    echo -e "${YELLOW}[1] Subdomain tarama${NC}"
    subfinder -d "$domain" -silent > "$outdir/subs.txt" 2>/dev/null || echo -e "${RED}[-] Subfinder başarısız oldu${NC}"
    
    # assetfinder kaldırıldı, sadece subfinder ve amass kullanılıyor
    amass enum -passive -d "$domain" | anew "$outdir/subs.txt" 2>/dev/null || echo -e "${RED}[-] Amass başarısız oldu${NC}"

    ## DNS çözümleme
    if [ -s "$outdir/subs.txt" ]; then
        dnsx -l "$outdir/subs.txt" -silent -a -o "$outdir/resolved_subs.txt" 2>/dev/null || echo -e "${RED}[-] DNSx başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Subdomain bulunamadı, DNS çözümleme atlanıyor${NC}"
    fi

    ## HTTP canlılık
    echo -e "${YELLOW}[2] HTTP canlılık testi${NC}"
    if [ -s "$outdir/resolved_subs.txt" ]; then
        httpx -l "$outdir/resolved_subs.txt" -silent -title -tech-detect -status-code > "$outdir/httpx_raw.txt" 2>/dev/null || echo -e "${RED}[-] httpx başarısız oldu${NC}"
        cut -d' ' -f1 "$outdir/httpx_raw.txt" > "$outdir/live.txt" 2>/dev/null
    else
        echo -e "${RED}[-] Çözümlenmiş subdomain bulunamadı, HTTP canlılık testi atlanıyor${NC}"
    fi

    ## Wayback endpoint
    echo -e "${YELLOW}[3] Wayback URL toplama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        gau < "$outdir/live.txt" | grep -iE "\.php|\.aspx|\.jsp|\.json|\.js|=" | anew "$outdir/waybacks.txt" 2>/dev/null || echo -e "${RED}[-] gau başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Wayback taraması atlanıyor${NC}"
    fi

    ## JS Linkleri
    echo -e "${YELLOW}[4] JavaScript linkleri toplama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        getJS --input "$outdir/live.txt" --output "$outdir/js_links.txt" 2>/dev/null || echo -e "${RED}[-] getJS başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, JS link toplama atlanıyor${NC}"
    fi

    ## XSS testi
    echo -e "${YELLOW}[5] XSS testi${NC}"
    if [ -s "$outdir/waybacks.txt" ]; then
        gf xss < "$outdir/waybacks.txt" | qsreplace '"><script>alert(1)</script>' | httpx -silent -status-code -location > "$outdir/xss.txt" 2>/dev/null || echo -e "${RED}[-] XSS testi başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, XSS testi atlanıyor${NC}"
    fi

    ## SQLi testi
    echo -e "${YELLOW}[6] SQLi testi${NC}"
    if [ -s "$outdir/waybacks.txt" ]; then
        gf sqli < "$outdir/waybacks.txt" | qsreplace "' OR '1'='1" | httpx -silent -status-code -location > "$outdir/sqli.txt" 2>/dev/null || echo -e "${RED}[-] SQLi testi başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, SQLi testi atlanıyor${NC}"
    fi

    ## Nuclei
    echo -e "${YELLOW}[7] Nuclei taraması${NC}"
    if [ -s "$outdir/live.txt" ]; then
        nuclei -l "$outdir/live.txt" -t cves/ -o "$outdir/nuclei-cves.txt" 2>/dev/null || echo -e "${RED}[-] Nuclei (CVEs) başarısız oldu${NC}"
        nuclei -l "$outdir/live.txt" -t exposures/ -t misconfiguration/ -t vulnerabilities/ -o "$outdir/nuclei-all.txt" 2>/dev/null || echo -e "${RED}[-] Nuclei (all) başarısız oldu${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Nuclei taraması atlanıyor${NC}"
    fi

    ## Dirsearch
    echo -e "${YELLOW}[8] Dizin tarama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        while IFS= read -r url; do
            dirsearch -u "$url" -e php,html,js,json,txt -w "$WORDLIST" --full-url -q -o "$outdir/dirsearch-${url//[:\/]/_}.txt" 2>/dev/null || echo -e "${RED}[-] Dirsearch ($url) başarısız oldu${NC}"
        done < "$outdir/live.txt"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Dizin taraması atlanıyor${NC}"
    fi

    echo -e "${GREEN}✅ $target taraması tamamlandı. Çıktılar: $outdir${NC}"
done

echo -e "${GREEN}🎉 Tüm hedefler AutoReconX ile başarıyla tarandı!${NC}"