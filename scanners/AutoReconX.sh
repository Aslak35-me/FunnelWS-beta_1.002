#!/bin/bash

set -e

# Renkli çıktılar için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

CONFIG_PATH="$(dirname "$0")/../config/setting.json"
OUTER_DIR="results"
WORDLIST="${WORDLIST:-~/SecLists/Discovery/Web-Content/raft-medium-words.txt}"

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
    
    # 1. Ping kontrolü (3 deneme, 2 saniye timeout)
    if ping -c 3 -W 2 "$host" &>/dev/null; then
        echo -e "${GREEN}[+] Ping başarılı: $host${NC}"
        
        # 2. HTTP/HTTPS erişim kontrolü (curl ile)
        http_code=$(curl --max-time 10 -k -s -I -o /dev/null -w "%{http_code}" "$target" || true)
        
        if [[ "$http_code" =~ ^[23] ]]; then
            echo -e "${GREEN}[+] HTTP erişimi başarılı: $target (Status: $http_code)${NC}"
            return 0
        else
            echo -e "${RED}[-] HTTP erişimi başarısız: $target (Status: ${http_code:-"Connection failed"})${NC}"
            return 1
        fi
    else
        echo -e "${RED}[-] Ping başarısız: $host${NC}"
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
    fi
done

# Hiçbir aktif hedef yoksa çık
if [ ${#active_targets[@]} -eq 0 ]; then
    echo -e "${RED}[!] Hiçbir aktif hedef bulunamadı. Çıkılıyor.${NC}"
    exit 1
fi

# Aktif hedefler için tarama başlat
for target in "${active_targets[@]}"; do
    domain=$(echo "$target" | sed -E 's#https?://([^:/]+).*#\1#')
    outdir="$OUTER_DIR/$domain"
    mkdir -p "$outdir"

    echo -e "${YELLOW}🔎 $target için tarama başlatılıyor...${NC}"

    ## Subdomain tarama
    echo -e "${YELLOW}[1] Subdomain tarama${NC}"
    subfinder -d "$domain" -silent > "$outdir/subs.txt"
    assetfinder --subs-only "$domain" | anew "$outdir/subs.txt"
    amass enum -passive -d "$domain" | anew "$outdir/subs.txt"

    ## DNS çözümleme
    dnsx -l "$outdir/subs.txt" -silent -a -o "$outdir/resolved_subs.txt"

    ## HTTP canlılık
    echo -e "${YELLOW}[2] HTTP canlılık testi${NC}"
    httpx -l "$outdir/resolved_subs.txt" -silent -title -tech-detect -status-code > "$outdir/httpx_raw.txt"
    cut -d' ' -f1 "$outdir/httpx_raw.txt" > "$outdir/live.txt"

    ## Wayback endpoint
    echo -e "${YELLOW}[3] Wayback URL toplama${NC}"
    gau < "$outdir/live.txt" | grep -iE "\.php|\.aspx|\.jsp|\.json|\.js|=" | anew "$outdir/waybacks.txt"

    ## JS Linkleri
    echo -e "${YELLOW}[4] JavaScript linkleri toplama${NC}"
    getJS --input "$outdir/live.txt" --output "$outdir/js_links.txt"

    ## XSS testi
    echo -e "${YELLOW}[5] XSS testi${NC}"
    gf xss < "$outdir/waybacks.txt" | qsreplace '"><script>alert(1)</script>' | httpx -silent -status-code -location > "$outdir/xss.txt"

    ## SQLi testi
    echo -e "${YELLOW}[6] SQLi testi${NC}"
    gf sqli < "$outdir/waybacks.txt" | qsreplace "' OR '1'='1" | httpx -silent -status-code -location > "$outdir/sqli.txt"

    ## Nuclei
    echo -e "${YELLOW}[7] Nuclei taraması${NC}"
    nuclei -l "$outdir/live.txt" -t cves/ -o "$outdir/nuclei-cves.txt"
    nuclei -l "$outdir/live.txt" -t exposures/ -t misconfiguration/ -t vulnerabilities/ -o "$outdir/nuclei-all.txt"

    ## Dirsearch
    echo -e "${YELLOW}[8] Dizin tarama${NC}"
    while IFS= read -r url; do
        dirsearch -u "$url" -e php,html,js,json,txt -w "$WORDLIST" --full-url -q -o "$outdir/dirsearch-${url//[:\/]/_}.txt"
    done < "$outdir/live.txt"

    echo -e "${GREEN}✅ $target taraması tamamlandı. Çıktılar: $outdir${NC}"
done

echo -e "${GREEN}🎉 Tüm hedefler AutoReconX ile başarıyla tarandı!${NC}"