import json
import os
from typing import List

def load_targets() -> List[str]:
    """
    settings.json'dan veya target dosyasından hedefleri yükler
    
    Returns:
        List[str]: Tarama yapılacak hedef URL'lerin listesi
    """
    try:
        # settings.json dosyasını oku
        with open('config/settings.json', 'r') as f:
            settings = json.load(f)
        
        # Eğer target file check aktifse
        if settings.get('TARGET_FILE_CHECK', 'off').lower() == 'on':
            target_file = settings.get('TARGET_FILE_PATH', 'targets.txt')
            
            # Target dosyasını oku ve temizle
            if os.path.exists(target_file):
                with open(target_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                # Geçerli URL'leri filtrele
                valid_targets = []
                for target in targets:
                    if target.startswith(('http://', 'https://')):
                        valid_targets.append(target)
                    else:
                        valid_targets.append(f'http://{target}')
                
                print(f"[+] {len(valid_targets)} hedef yüklendi")
                return valid_targets
            else:
                print(f"[!] Target dosyası bulunamadı: {target_file}")
                return []
        else:
            # Tekil target kullan
            target = settings.get('TARGET', '')
            if not target:
                print("[!] settings.json'da TARGET belirtilmemiş")
                return []
            
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            return [target]
            
    except Exception as e:
        print(f"[!] Target yükleme hatası: {e}")
        return []