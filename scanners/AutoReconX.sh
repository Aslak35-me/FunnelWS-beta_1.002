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

# Başlangıç mesajı
echo -e "${GREEN}[*] AutoReconX.sh başlatılıyor...${NC}"

# Betiğin gerçek yolunu bul
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# GPG anahtar sorununu çöz (modern yöntem)
fix_gpg() {
    echo -e "${YELLOW}[*] GPG anahtar sorunları çözülüyor...${NC}"
    
    # Dağıtımı tespit et
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case $ID in
            kali)
                # Kali Linux arşiv anahtarını ekle
                wget -q -O /tmp/kali-archive-key.asc https://archive.kali.org/archive-key.asc
                sudo gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg /tmp/kali-archive-key.asc
                rm -f /tmp/kali-archive-key.asc
                ;;
            ubuntu|debian)
                # Ubuntu/Debian anahtarlarını yükle
                sudo apt-get update && sudo apt-get install -y ubuntu-keyring debian-archive-keyring
                ;;
            *)
                echo -e "${YELLOW}[!] Uyarı: $ID dağıtımı için otomatik GPG anahtar yönetimi desteklenmiyor${NC}"
                echo -e "${YELLOW}[!] Lütfen manuel olarak gerekli GPG anahtarlarını ekleyin${NC}"
                return 1
                ;;
        esac
    else
        echo -e "${RED}[!] Hata: Sistem dağıtımı tespit edilemedi!${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] GPG anahtar sorunları çözüldü${NC}"
    echo -e "${YELLOW}[!] NOT: 'apt-key' kullanımdan kaldırıldığı için modern GPG anahtar yönetimi kullanılmıştır.${NC}"
}

# PATH güncelleme
update_path() {
    local paths_to_add=("$BIN_DIR" "$HOME/go/bin" "/usr/local/go/bin")
    
    for path in "${paths_to_add[@]}"; do
        if [[ ":$PATH:" != *":$path:"* ]]; then
            echo -e "${YELLOW}[+] PATH'e $path ekleniyor...${NC}"
            for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
                if [ -f "$rcfile" ]; then
                    if ! grep -q "export PATH=\"\$PATH:$path\"" "$rcfile"; then
                        echo "export PATH=\"\$PATH:$path\"" >> "$rcfile"
                    fi
                fi
            done
            export PATH="$PATH:$path"
        fi
    done
    
    echo -e "${YELLOW}[!] PATH değişikliklerinin etkili olması için yeni bir terminal açın veya:${NC}"
    echo -e "${YELLOW}[!] source ~/.bashrc  veya  source ~/.zshrc komutunu çalıştırın${NC}"
}

# Versiyon karşılaştırma fonksiyonu
version_compare() {
    local ver1=$(echo "$1" | sed 's/[^0-9.]//g')
    local ver2=$(echo "$2" | sed 's/[^0-9.]//g')
    
    if [ "$ver1" = "$ver2" ]; then
        return 0
    fi
    
    local IFS=.
    local i ver1=($ver1) ver2=($ver2)
    
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

# Go kurulumu (en yeni sürüm)
install_go() {
    local required_version="1.21"
    
    if command -v go &> /dev/null; then
        local current_version=$(go version | awk '{print $3}' | sed 's/go//')
        version_compare "$current_version" "$required_version"
        if [ $? -ge 1 ]; then
            echo -e "${YELLOW}[+] Go zaten yüklü: $(go version)${NC}"
            return 0
        else
            echo -e "${YELLOW}[!] Go sürümü ($current_version) gereken sürümden ($required_version) eski${NC}"
            echo -e "${YELLOW}[!] Mevcut Go kurulumu (/usr/local/go) güncellenecek. Devam edilsin mi? (e/H): ${NC}"
            read -r confirmation
            if [[ "$confirmation" != "e" && "$confirmation" != "E" ]]; then
                echo -e "${RED}[!] Go kurulumu kullanıcı tarafından iptal edildi.${NC}"
                return 1
            fi
        fi
    fi
    
    echo -e "${BLUE}[*] Go $required_version+ kurulumu...${NC}"
    sudo rm -rf /usr/local/go
    
    # Go sürümünü güvenli şekilde al
    local latest_go=$(curl -s https://go.dev/VERSION?m=text | head -n 1 | tr -d '\n')
    if [[ -z "$latest_go" ]]; then
        latest_go="go1.21.0" # Fallback sürüm
    fi
    
    echo -e "${YELLOW}[*] $latest_go indiriliyor...${NC}"
    if ! wget "https://dl.google.com/go/${latest_go}.linux-amd64.tar.gz" -O /tmp/go.tar.gz; then
        echo -e "${RED}[!] Go indirme başarısız, alternatif URL deniyor...${NC}"
        wget "https://go.dev/dl/${latest_go}.linux-amd64.tar.gz" -O /tmp/go.tar.gz || {
            echo -e "${RED}[!] Go indirme başarısız oldu!${NC}"
            return 1
        }
    fi

    # Checksum doğrulama (basit versiyon)
    echo -e "${YELLOW}[*] Go tarball boyutu kontrol ediliyor...${NC}"
    local filesize=$(stat -c%s "/tmp/go.tar.gz")
    if [ "$filesize" -lt 100000000 ]; then  # ~100MB'den küçükse şüpheli
        echo -e "${RED}[!] İndirilen Go tarball boyutu çok küçük, dosya bozuk olabilir!${NC}"
        echo -e "${YELLOW}[!] Lütfen manuel olarak kontrol edin: https://go.dev/dl/${NC}"
        rm -f /tmp/go.tar.gz
        return 1
    fi

    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    
    # Go sürümünü doğrula
    if ! /usr/local/go/bin/go version &>/dev/null; then
        echo -e "${RED}[!] Go kurulumu doğrulanamadı!${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] Go $latest_go kuruldu: $(/usr/local/go/bin/go version)${NC}"
}

# Python kurulumu
install_python() {
    if ! command -v python3 &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${BLUE}[*] Python/pip kurulumu...${NC}"
        sudo apt update && sudo apt install -y python3 python3-pip python3-venv
        echo -e "${GREEN}[+] Python kuruldu${NC}"
    else
        echo -e "${YELLOW}[+] Python zaten yüklü: $(python3 --version)${NC}"
    fi
}

# Go araç kurulumu (mod desteği ile)
install_go_tool() {
    local tool=$1
    local pkg=$2
    
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${BLUE}[*] $tool kurulumu...${NC}"
        GO111MODULE=on go install "$pkg@latest"
        
        # Kurulumu doğrula
        if command -v "$tool" &> /dev/null; then
            # Çeşitli sürüm komut formatlarını dene
            local version=$($tool -version 2>/dev/null || $tool --version 2>/dev/null || $tool version 2>/dev/null || $tool -v 2>/dev/null || echo 'sürüm bilgisi yok')
            echo -e "${GREEN}[+] $tool kuruldu ($version)${NC}"
        else
            echo -e "${RED}[-] $tool kurulumu başarısız oldu!${NC}"
            return 1
        fi
    else
        # Çeşitli sürüm komut formatlarını dene
        local version=$($tool -version 2>/dev/null || $tool --version 2>/dev/null || $tool version 2>/dev/null || $tool -v 2>/dev/null || echo 'sürüm bilgisi yok')
        echo -e "${YELLOW}[+] $tool zaten yüklü ($version)${NC}"
    fi
}

# Sistem bağımlılıklarını kur
install_system_deps() {
    echo -e "${BLUE}[*] Sistem bağımlılıkları kontrol ediliyor...${NC}"
    
    # Önce GPG sorununu çöz
    if ! fix_gpg; then
        echo -e "${YELLOW}[!] GPG anahtar sorunları çözülemedi, bazı işlemler başarısız olabilir${NC}"
    fi
    
    # Paket listesini güncelle (sadece bir kez)
    if ! sudo apt update; then
        echo -e "${RED}[!] apt update başarısız oldu!${NC}"
        return 1
    fi
    
    sudo apt install -y git wget build-essential libssl-dev zlib1g-dev jq
    
    # Kullanılmayan paketleri temizle
    sudo apt autoremove -y
}

# Nuclei template'lerini güncelle
update_nuclei_templates() {
    if command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[*] Nuclei template'leri güncelleniyor...${NC}"
        nuclei -update-templates 2>&1 | while read -r line; do
            echo -e "${YELLOW}[nuclei] $line${NC}"
        done
        echo -e "${GREEN}[+] Nuclei template güncellemesi tamamlandı${NC}"
    else
        echo -e "${YELLOW}[!] Nuclei kurulu değil, template güncelleme atlanıyor${NC}"
    fi
}

# Ana kurulum fonksiyonu
install_dependencies() {
    # Sistem bağımlılıkları
    if ! install_system_deps; then
        echo -e "${RED}[!] Sistem bağımlılıkları kurulumu başarısız oldu!${NC}"
        exit 1
    fi

    # Go kurulum
    if ! install_go; then
        echo -e "${RED}[!] Go kurulumu başarısız oldu!${NC}"
        exit 1
    fi
    update_path

    # Python kurulum
    install_python

    # Go araçları
    declare -A go_tools=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        ["amass"]="github.com/owasp-amass/amass/v3/cmd/amass"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
        ["gau"]="github.com/lc/gau/v2/cmd/gau"
        ["getJS"]="github.com/003random/getJS"
        ["gf"]="github.com/tomnomnom/gf"
        ["qsreplace"]="github.com/tomnomnom/qsreplace"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
        ["anew"]="github.com/tomnomnom/anew"  # anew eklendi
    )

    for tool in "${!go_tools[@]}"; do
        if ! install_go_tool "$tool" "${go_tools[$tool]}"; then
            echo -e "${YELLOW}[!] Uyarı: $tool kurulumu başarısız oldu, bazı özellikler çalışmayabilir${NC}"
        fi
    done

    # Python araçları
    echo -e "${BLUE}[*] dirsearch kurulumu...${NC}"
    pip3 install --user dirsearch || {
        echo -e "${RED}[-] dirsearch kurulumu başarısız oldu!${NC}"
    }

    # GF patternleri
    if [ ! -d "$HOME/.gf" ]; then
        echo -e "${BLUE}[*] GF patternleri indiriliyor...${NC}"
        mkdir -p "$HOME/.gf"
        if git clone https://github.com/tomnomnom/gf "$TOOLS_DIR/gf"; then
            cp -r "$TOOLS_DIR/gf/examples" "$HOME/.gf/"
            for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
                if [ -f "$rcfile" ]; then
                    if ! grep -q "source \$HOME/.gf/gf-completion.bash" "$rcfile"; then
                        echo 'source $HOME/.gf/gf-completion.bash' >> "$rcfile"
                    fi
                fi
            done
        else
            echo -e "${RED}[-] GF pattern indirme başarısız oldu!${NC}"
            return 1
        fi
    fi

    # Nuclei template güncellemesi
    update_nuclei_templates

    # Go modülleri temizleme
    go clean -modcache
}

# Kurulumu başlat
install_dependencies

echo -e "${GREEN}[✔] Tüm bağımlılıklar başarıyla kuruldu!${NC}"

# Ana script devamı...
CONFIG_PATH="$SCRIPT_DIR/../config/setting.json"
OUTER_DIR="results"
WORDLIST="${WORDLIST:-$HOME/SecLists/Discovery/Web-Content/raft-medium-words.txt}"

# Eğer SecLists yoksa kur
if [ ! -d "$HOME/SecLists" ]; then
    echo -e "${YELLOW}[*] SecLists indiriliyor...${NC}"
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"; then
        echo -e "${GREEN}[+] SecLists başarıyla indirildi${NC}"
    else
        echo -e "${RED}[-] SecLists indirme başarısız oldu!${NC}"
        echo -e "${YELLOW}[!] Alternatif bir kelime listesi kullanabilirsiniz:${NC}"
        echo -e "${YELLOW}[!] WORDLIST=/path/to/wordlist.txt ./AutoReconX.sh${NC}"
    fi
fi

# JSON config'ini oku
if [ ! -f "$CONFIG_PATH" ]; then
    echo -e "${RED}[!] Hata: Config dosyası bulunamadı: $CONFIG_PATH${NC}"
    exit 1
fi

# JSON config'ini oku
TARGET_FILE_CHECK=$(jq -r '.TARGET_FILE_CHECK' "$CONFIG_PATH")
TARGET=$(jq -r '.TARGET' "$CONFIG_PATH")
TARGET_FILE_PATH=$(jq -r '.TARGET_FILE_PATH' "$CONFIG_PATH")
DORK_CHECK=$(jq -r '.DORK_CHECK' "$CONFIG_PATH")
DORK_FILE_CHECK=$(jq -r '.DORK_FILE_CHECK' "$CONFIG_PATH")

# Hedef listesi oluştur
targets=()

# DORK_CHECK veya DORK_FILE_CHECK aktifse, dork_output.txt'den hedefleri oku
if [[ "$DORK_CHECK" == "on" || "$DORK_FILE_CHECK" == "on" ]]; then
    DORK_OUTPUT_FILE="results/dork_output.txt"
    if [ -f "$DORK_OUTPUT_FILE" ]; then
        echo -e "${YELLOW}[*] Hedefler dork_output.txt dosyasından okunuyor${NC}"
        # Sadece http:// veya https:// ile başlayan satırları al
        while IFS= read -r line; do
            if [[ "$line" =~ ^https?:// ]]; then
                targets+=("$line")
            fi
        done < "$DORK_OUTPUT_FILE"
    else
        echo -e "${RED}[!] Hata: dork_output.txt dosyası bulunamadı!${NC}"
        exit 1
    fi
elif [[ "$TARGET_FILE_CHECK" == "on" ]]; then
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
    local http_code=$(curl --max-time 10 -k -s -I -o /dev/null -w "%{http_code}" "$target" 2>/dev/null || true)
    
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
    # Eğer http:// veya https:// yoksa ekle (DORK_CHECK durumunda zaten var)
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
    subfinder -d "$domain" -silent > "$outdir/subs.txt" 2>"$OUTER_DIR/logs/subfinder_$domain.log" || echo -e "${RED}[-] Subfinder başarısız oldu, log: $OUTER_DIR/logs/subfinder_$domain.log${NC}"
    
    # assetfinder kaldırıldı, sadece subfinder ve amass kullanılıyor
    amass enum -passive -d "$domain" 2>"$OUTER_DIR/logs/amass_$domain.log" | anew "$outdir/subs.txt" || echo -e "${RED}[-] Amass başarısız oldu, log: $OUTER_DIR/logs/amass_$domain.log${NC}"

    ## DNS çözümleme
    if [ -s "$outdir/subs.txt" ]; then
        dnsx -l "$outdir/subs.txt" -silent -a -o "$outdir/resolved_subs.txt" 2>"$OUTER_DIR/logs/dnsx_$domain.log" || echo -e "${RED}[-] DNSx başarısız oldu, log: $OUTER_DIR/logs/dnsx_$domain.log${NC}"
    else
        echo -e "${RED}[-] Subdomain bulunamadı, DNS çözümleme atlanıyor${NC}"
    fi

    ## HTTP canlılık
    echo -e "${YELLOW}[2] HTTP canlılık testi${NC}"
    if [ -s "$outdir/resolved_subs.txt" ]; then
        httpx -l "$outdir/resolved_subs.txt" -silent -title -tech-detect -status-code > "$outdir/httpx_raw.txt" 2>"$OUTER_DIR/logs/httpx_$domain.log" || echo -e "${RED}[-] httpx başarısız oldu, log: $OUTER_DIR/logs/httpx_$domain.log${NC}"
        cut -d' ' -f1 "$outdir/httpx_raw.txt" > "$outdir/live.txt" 2>/dev/null
    else
        echo -e "${RED}[-] Çözümlenmiş subdomain bulunamadı, HTTP canlılık testi atlanıyor${NC}"
    fi

    ## Wayback endpoint
    echo -e "${YELLOW}[3] Wayback URL toplama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        gau < "$outdir/live.txt" 2>"$OUTER_DIR/logs/gau_$domain.log" | grep -iE "\.php|\.aspx|\.jsp|\.json|\.js|=" | anew "$outdir/waybacks.txt" || echo -e "${RED}[-] gau başarısız oldu, log: $OUTER_DIR/logs/gau_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Wayback taraması atlanıyor${NC}"
    fi

    ## JS Linkleri
    echo -e "${YELLOW}[4] JavaScript linkleri toplama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        getJS --input "$outdir/live.txt" --output "$outdir/js_links.txt" 2>"$OUTER_DIR/logs/getJS_$domain.log" || echo -e "${RED}[-] getJS başarısız oldu, log: $OUTER_DIR/logs/getJS_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, JS link toplama atlanıyor${NC}"
    fi

    ## XSS testi
    echo -e "${YELLOW}[5] XSS testi${NC}"
    if [ -s "$outdir/waybacks.txt" ]; then
        gf xss < "$outdir/waybacks.txt" | qsreplace '"><script>alert(1)</script>' | httpx -silent -status-code -location > "$outdir/xss.txt" 2>"$OUTER_DIR/logs/xss_$domain.log" || echo -e "${RED}[-] XSS testi başarısız oldu, log: $OUTER_DIR/logs/xss_$domain.log${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, XSS testi atlanıyor${NC}"
    fi

    ## SQLi testi
    echo -e "${YELLOW}[6] SQLi testi${NC}"
    if [ -s "$outdir/waybacks.txt" ]; then
        gf sqli < "$outdir/waybacks.txt" | qsreplace "' OR '1'='1" | httpx -silent -status-code -location > "$outdir/sqli.txt" 2>"$OUTER_DIR/logs/sqli_$domain.log" || echo -e "${RED}[-] SQLi testi başarısız oldu, log: $OUTER_DIR/logs/sqli_$domain.log${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, SQLi testi atlanıyor${NC}"
    fi

    ## Nuclei
    echo -e "${YELLOW}[7] Nuclei taraması${NC}"
    if [ -s "$outdir/live.txt" ]; then
        nuclei -l "$outdir/live.txt" -t cves/ -o "$outdir/nuclei-cves.txt" 2>"$OUTER_DIR/logs/nuclei-cves_$domain.log" || echo -e "${RED}[-] Nuclei (CVEs) başarısız oldu, log: $OUTER_DIR/logs/nuclei-cves_$domain.log${NC}"
        nuclei -l "$outdir/live.txt" -t exposures/ -t misconfiguration/ -t vulnerabilities/ -o "$outdir/nuclei-all.txt" 2>"$OUTER_DIR/logs/nuclei-all_$domain.log" || echo -e "${RED}[-] Nuclei (all) başarısız oldu, log: $OUTER_DIR/logs/nuclei-all_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Nuclei taraması atlanıyor${NC}"
    fi

    ## Dirsearch
    echo -e "${YELLOW}[8] Dizin tarama${NC}"
    if [ -s "$outdir/live.txt" ]; then
        while IFS= read -r url; do
            safe_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            dirsearch -u "$url" -e php,html,js,json,txt -w "$WORDLIST" --full-url -q -o "$outdir/dirsearch-${safe_url}.txt" 2>"$OUTER_DIR/logs/dirsearch_${safe_url}.log" || echo -e "${RED}[-] Dirsearch ($url) başarısız oldu, log: $OUTER_DIR/logs/dirsearch_${safe_url}.log${NC}"
        done < "$outdir/live.txt"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Dizin taraması atlanıyor${NC}"
    fi

    echo -e "${GREEN}✅ $target taraması tamamlandı. Çıktılar: $outdir${NC}"
done

echo -e "${GREEN}🎉 Tüm hedefler AutoReconX ile başarıyla tarandı!${NC}"