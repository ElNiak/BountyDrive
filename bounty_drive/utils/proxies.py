#########################################################################################
# Proxy related functions
#########################################################################################

# Round-robin proxy generator
import itertools

import requests
from termcolor import cprint
from tqdm import tqdm


def round_robin_proxies(proxies):
    return itertools.cycle(proxies)
    
# Function to check if a proxy is up
def is_proxy_alive(proxy):
    try:
        response = requests.get('http://www.google.com', 
                                proxies={"http": proxy, "https": proxy}, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False
    
# Load proxies from file
def load_proxies(file="proxies/free-proxy-list.txt"):
    with open(file, 'r') as file:
        return [line.strip() for line in file if line.strip()]
    
def setup_proxies():
    proxies = load_proxies()
    proxies_cp = proxies.copy()
    dead_proxies  = 0
    total_proxies = len(proxies) 
        # TODO init website lists from file
    for proxy in tqdm(proxies_cp, desc="Checking proxies", unit="proxy"):
        if not is_proxy_alive(proxy):
            dead_proxies += 1
            cprint(f"Removing dead proxy {proxy}, dead proxies {dead_proxies}/{total_proxies}", 'red', file=sys.stderr)
            proxies.remove(proxy)
    cprint(f"Up proxies: {len(proxies)}")
    return proxies