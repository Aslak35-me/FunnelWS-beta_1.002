#!/bin/bash

set -e

CONFIG_PATH="config/settings.json"
OUTER_DIR="results"
WORDLIST="${WORDLIST:-~/SecLists/Discovery/Web-Content/raft-medium-words.txt}"

# JSON config'ini oku
TARGET_FILE_CHECK=$(jq -r '.TARGET_FILE_CHECK' "$CONFIG_PATH")
TARGET=$(jq -r '.TARGET' "$CONFIG_PATH")
TARGET_FILE_PATH=$(jq -r '.TARGET_FILE_PATH' "$CONFIG_PATH")

# Hedef listesi oluştur
targets=()

if [[ "$TARGET_FILE_CHECK" == "on" ]]; then
    echo "[*] Hedefler dosyadan okunuyor: $TARGET_FILE_PATH"
    while IFS= read -r line; do
        cleaned=$(echo "$line" | xargs)
        if [[ -n "$cleaned" ]]; then
            targets+=("$cleaned")
        fi
    done < "$TARGET_FILE_PATH"
else
    echo "[*] Tek hedef kullanılacak: $TARGET"
    targets+=("$TARGET")
fi

# Aktif hedefleri kontrol et
active_targets=()
mkdir -p "$OUTER_DIR/logs"

echo "[*] Canlı hedefler kontrol ediliyor..."
for target in "${targets[@]}"; do
    # Domain veya IP’ye ping
    host=$(echo "$target" | sed -E 's#(https?://)?([^:/]+).*#\2#')
    if ping -c 1 -W 1 "$host" &>/dev/null; then
        # httpx ile 200 OK mi kontrol et
        result=$(echo "$target" | httpx -silent -status-code)
        if echo "$result" | grep -q "\[200\]"; then
            echo "[+] Canlı: $target"
            active_targets+=("$target")
        else
            echo "[-] HTTP kontrolü başarısız: $target"
        fi
    else
        echo "[-] Ping başarısız: $target"
    fi
done

# Hiçbir aktif hedef yoksa çık
if [ ${#active_targets[@]} -eq 0 ]; then
    echo "[!] Hiçbir aktif hedef bulunamadı. Çıkılıyor."
    exit 1
fi

# Aktif hedefler için tarama başlat
for target in "${active_targets[@]}"; do
    domain=$(echo "$target" | sed -E 's#https?://([^:/]+).*#\1#')
    outdir="$OUTER_DIR/$domain"
    mkdir -p "$outdir"

    echo "🔎 $target için tarama başlatılıyor..."

    ## Subdomain tarama
    echo "[1] Subdomain tarama"
    subfinder -d "$domain" -silent > "$outdir/subs.txt"
    assetfinder --subs-only "$domain" | anew "$outdir/subs.txt"
    amass enum -passive -d "$domain" | anew "$outdir/subs.txt"

    ## DNS çözümleme
    dnsx -l "$outdir/subs.txt" -silent -a -o "$outdir/resolved_subs.txt"

    ## HTTP canlılık
    echo "[2] HTTP canlılık testi"
    httpx -l "$outdir/resolved_subs.txt" -silent -title -tech-detect -status-code > "$outdir/httpx_raw.txt"
    cut -d' ' -f1 "$outdir/httpx_raw.txt" > "$outdir/live.txt"

    ## Wayback endpoint
    echo "[3] Wayback URL toplama"
    gau < "$outdir/live.txt" | grep -iE "\.php|\.aspx|\.jsp|\.json|\.js|=" | anew "$outdir/waybacks.txt"

    ## JS Linkleri
    echo "[4] JavaScript linkleri toplama"
    getJS --input "$outdir/live.txt" --output "$outdir/js_links.txt"

    ## XSS testi
    echo "[5] XSS testi"
    gf xss < "$outdir/waybacks.txt" | qsreplace '"><script>alert(1)</script>' | httpx -silent -status-code -location > "$outdir/xss.txt"

    ## SQLi testi
    echo "[6] SQLi testi"
    gf sqli < "$outdir/waybacks.txt" | qsreplace "' OR '1'='1" | httpx -silent -status-code -location > "$outdir/sqli.txt"

    ## Nuclei
    echo "[7] Nuclei taraması"
    nuclei -l "$outdir/live.txt" -t cves/ -o "$outdir/nuclei-cves.txt"
    nuclei -l "$outdir/live.txt" -t exposures/ -t misconfiguration/ -t vulnerabilities/ -o "$outdir/nuclei-all.txt"

    ## Dirsearch
    echo "[8] Dizin tarama"
    while IFS= read -r url; do
        dirsearch -u "$url" -e php,html,js,json,txt -w "$WORDLIST" --full-url -q -o "$outdir/dirsearch-${url//[:\/]/_}.txt"
    done < "$outdir/live.txt"

    echo "✅ $target taraması tamamlandı. Çıktılar: $outdir"
done

echo "🎉 Tüm hedefler AutoReconX ile başarıyla tarandı!"
