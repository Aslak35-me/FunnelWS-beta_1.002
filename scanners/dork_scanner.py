import json
import os
import requests
from colorama import init, Fore, Style
from bs4 import BeautifulSoup

# Initialize colorama
init()

# Configuration
SETTING_FILE = "config/setting.json"
OUTPUT_FILE = "results/dork_output.txt"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def load_dork():
    try:
        with open(SETTING_FILE, 'r') as f:
            config = json.load(f)
            return config.get("DORK", "")
    except FileNotFoundError:
        print(Fore.RED + f"Error: {SETTING_FILE} not found!" + Style.RESET_ALL)
        return ""
    except json.JSONDecodeError:
        print(Fore.RED + f"Error: Invalid JSON in {SETTING_FILE}!" + Style.RESET_ALL)
        return ""

def setup_directories():
    # Create results directory if not exists
    if not os.path.exists("results"):
        os.makedirs("results")
    
    # Create output file if not exists
    if not os.path.exists(OUTPUT_FILE):
        open(OUTPUT_FILE, 'w').close()

def bing_search(query):
    try:
        url = f"https://www.bing.com/search?q={query}"
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        
        for li in soup.find_all('li', class_='b_algo'):
            link = li.find('a')
            if link and 'href' in link.attrs:
                results.append(link['href'])
        
        return results
    except requests.RequestException as e:
        print(Fore.RED + f"Error during Bing search: {e}" + Style.RESET_ALL)
        return []

def save_results(urls):
    with open(OUTPUT_FILE, 'w') as f:
        for url in urls:
            f.write(url + '\n')

def print_results(urls):
    print(Fore.GREEN + "\nSearch Results:" + Style.RESET_ALL)
    for i, url in enumerate(urls, 1):
        print(Fore.CYAN + f"{i}. {url}" + Style.RESET_ALL)

def main():
    setup_directories()
    
    dork = load_dork()
    if not dork:
        return
    
    print(Fore.YELLOW + f"Searching Bing with dork: {dork}" + Style.RESET_ALL)
    
    results = bing_search(dork)
    
    if results:
        save_results(results)
        print_results(results)
        print(Fore.GREEN + f"\nResults saved to {OUTPUT_FILE}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "No results found." + Style.RESET_ALL)

if __name__ == "__main__":
    main()