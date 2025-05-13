import re
import requests
from bs4 import BeautifulSoup

def detect_versions(response):
    """Gelişmiş teknoloji ve versiyon tespiti"""
    technologies = {}
    
    # HTTP Header'dan tespit
    server = response.headers.get('Server', '')
    if server:
        technologies['Web Server'] = parse_technology(server)
    
    x_powered_by = response.headers.get('X-Powered-By', '')
    if x_powered_by:
        technologies['Backend'] = parse_technology(x_powered_by)
    
    # HTML içeriğinden tespit
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Meta tag'ler
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator and 'content' in meta_generator.attrs:
        technologies['Generator'] = parse_technology(meta_generator['content'])
    
    # Script ve CSS dosyaları
    for script in soup.find_all('script', src=True):
        src = script['src'].lower()
        if 'jquery' in src:
            version = re.search(r'jquery-(.*?)\.js', src)
            technologies['jQuery'] = {
                'version': version.group(1) if version else 'unknown',
                'category': 'JavaScript',
                'confidence': 'high'
            }
    
    # Sayfa içeriğinden framework ipuçları
    body_classes = soup.find('body').get('class', []) if soup.find('body') else []
    if any('wp-' in cls for cls in body_classes):
        technologies['WordPress'] = {
            'category': 'CMS',
            'confidence': 'medium'
        }
    
    return technologies

def parse_technology(tech_string):
    """Teknoloji string'ini ayrıştırır"""
    # Örnek: Apache/2.4.29 (Ubuntu)
    version_match = re.search(r'(\d+\.\d+(\.\d+)*)', tech_string)
    name_match = re.search(r'^([a-zA-Z]+)', tech_string)
    
    tech_name = name_match.group(1) if name_match else tech_string
    version = version_match.group(1) if version_match else 'unknown'
    
    return {
        'version': version,
        'raw': tech_string,
        'confidence': 'high' if version_match else 'medium'
    }