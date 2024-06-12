#########################################################################################
# Proxy related functions
#########################################################################################

# Round-robin proxy generator
import itertools
import threading

import requests
from termcolor import cprint
import concurrent.futures
from tqdm import tqdm
import sys 

def round_robin_proxies(proxies):
    return itertools.cycle(proxies)
    
# Function to check if a proxy is up
def is_proxy_alive(proxy):
    try:
        response = requests.get('http://www.google.com', 
                                proxies={"http": proxy, "https": proxy}, timeout=5, verify=False)
        return response.status_code == 200, proxy
    except requests.RequestException:
        return False, proxy
    
# Load proxies from file
def load_proxies(file="proxies/free-proxy-list.txt"):
    with open(file, 'r') as file:
        return [line.strip() for line in file if line.strip()]
    
def setup_proxies():
    proxies = load_proxies()
    proxies_cp = proxies.copy()
    dead_proxies  = 0
    total_proxies = len(proxies) 
            
    
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_search = {
            executor.submit(
                is_proxy_alive, proxy
            ): proxy
            for proxy in proxies_cp
        }
        for future in tqdm(
            concurrent.futures.as_completed(future_to_search),
            total=len(future_to_search),
            desc="Checking proxies",
            unit="proxy",
            leave=True,
            position=0
        ):
            result = future.result()
            if result:
                with lock:
                    if not result[0]:
                        dead_proxies += 1
                        cprint(f"Removing dead proxy {result[1]}, dead proxies {dead_proxies}/{total_proxies}", 'red', file=sys.stderr)
                        proxies.remove(result[1])
        cprint(f"Up proxies: {len(proxies)}")
               
    return proxies