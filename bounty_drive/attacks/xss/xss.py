#########################################################################################
# XSS Vulnerability testing functions
#########################################################################################
import glob
import sys

import requests
from termcolor import cprint
from tqdm import tqdm

from utils.app_config import POTENTIAL_PATHS, VULN_PATHS
from utils.request_manager import inject_payload
from utils.waf_mitigation import waf_detector

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Selenium and webdriver_manager modules not found. Please make sure they are installed.")
    sys.exit(1)

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

def test_vulnerability_xss(proxies):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    VULN_PATHS["xss"][1] = []

    s = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=s)
    
    XSS_TEST_PAYLOAD = load_xss_payload()
    if len(POTENTIAL_PATHS["xss"][1]) > 0:
        for website in tqdm(POTENTIAL_PATHS["xss"][1], desc=f"Testing for XSS for {website}", unit="site"):
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
                    VULN_PATHS["xss"][1].append(payload_url)
                else:
                    cprint(f"[NOT VULNERABLE] {payload_url}", "green", file=sys.stderr)
            
            if VULN_PATHS["xss"][1]:
                driver.execute_script("window.open('');")
                driver.switch_to.window(driver.window_handles[-1])
                for vulnerable_url in VULN_PATHS["xss"][1]:
                    driver.get(vulnerable_url)
