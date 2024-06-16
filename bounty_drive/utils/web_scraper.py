import os
import random
import re
import sys
import time
from urllib.parse import urljoin
import requests

# web_scraper.py
import requests
from bs4 import BeautifulSoup
from termcolor import cprint
from utils.nord_vpn_config import *
from utils.app_config import CURRENT_DELAY, REQUEST_DELAY, USER_AGENTS

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def fetch_html_content(url, proxy=None, headers=None):
    """
    Fetch the HTML content of a given URL.

    Args:
        url (str): The URL to fetch the content from.

    Returns:
        str: HTML content of the page or None if request fails.
    """
    try:
        cprint(f"Fetching {url}", color="yellow", file=sys.stderr)
        if "username:password" in proxy:
            nord_vpn_user_pass = random.choice(nord_vpn_login)
            proxy = proxy.replace("username", nord_vpn_user_pass[0]).replace(
                "password", nord_vpn_user_pass[1]
            )
            proxies = {"https": proxy}
            secured = True
        else:
            proxies = {"http": proxy, "https": proxy}
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        response = requests.Session().get(
            url,
            proxies=proxies,
            headers=headers,
            verify=secured,
            allow_redirects=True,
            timeout=REQUEST_DELAY,
        )
        delay = random.uniform(CURRENT_DELAY - 5, CURRENT_DELAY + 5)
        time.sleep(delay)  # Wait before retrying
        return response.text
    except requests.exceptions.ProxyError as e:
        cprint(
            f"ProxyError searching for {url} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(CURRENT_DELAY - 2, CURRENT_DELAY + 2)
        time.sleep(delay)  # Wait before retrying
        # TODO add backoff timer for delay ?
        return None
    except requests.exceptions.RequestException as e:
        cprint(
            f"RequestException searching for {url} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(CURRENT_DELAY - 5, CURRENT_DELAY + 5)
        time.sleep(delay)  # Wait before retrying
        return None


def extract_links(html_content, base_url):
    """
    Extract all href links from the HTML content and convert to absolute URLs.

    Args:
        html_content (str): HTML content of the page.
        base_url (str): The base URL to resolve relative URLs.

    Returns:
        list: List of absolute URLs found in the href attributes and other redirections.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    links = []

    # Extracting href attributes from anchor tags
    for anchor in soup.find_all("a", href=True):
        link = urljoin(base_url, anchor["href"])
        links.append(link)

    # Extracting other potential redirections (meta refresh, script-based)
    for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
        content = meta.get("content", "")
        if "url=" in content:
            link = urljoin(base_url, content.split("url=")[-1])
            links.append(link)

    # Handle common JavaScript redirection patterns
    for script in soup.find_all("script"):
        if script.string:
            js_urls = re.findall(
                r"window\.location\.href\s*=\s*['\"](.*?)['\"]", script.string
            )
            for js_url in js_urls:
                link = urljoin(base_url, js_url)
                links.append(link)

    print(f"Extracted {len(links)} links from {base_url}", file=sys.stderr)
    return links


def render_js_and_extract_links(url, html_content_get):
    """
    Use Selenium to render JavaScript and extract links.

    Args:
        url (str): URL of the page to scrape.

    Returns:
        list: List of absolute URLs found in the rendered HTML.
    """
    cprint(f"Rendering JavaScript for {url}", color="yellow", file=sys.stderr)
    options = Options()
    options.headless = True
    # service=Service('/path/to/chromedriver'),
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "body"))
    )
    html_content = driver.page_source
    driver.quit()
    return extract_links(html_content, url) + extract_links(html_content_get, url)


def scrape_links_from_url(url, proxy=None, headers=None):
    """
    Scrape all potential links and redirections from a given URL.

    Args:
        url (str): The URL to scrape.

    Returns:
        list: List of URLs found in the page.
    """

    cprint(f"Scraping links from {url}", color="yellow", file=sys.stderr)
    html_content = fetch_html_content(url, proxy=proxy, headers=headers)
    if html_content:
        return render_js_and_extract_links(url, html_content)
    return []


# https://github.com/DanMcInerney/xsscrapy/blob/master/xsscrapy.py
def crawl(url, urls):
    raise NotImplementedError("Crawling not implemented for now")
    return urls


# https://github.com/PercyJackson235/pydirbuster/blob/main/pydirbuster/main.py
def dirb(urls, wordlist):
    arr = []
    url = urls
    try:
        if url[:7] != "http://":
            url = "http://" + url
        r = requests.get(url)
        if r.status_code == 200:
            print("Host is up.")
        else:
            print("Host is down.")
            return
        if os.path.exists(os.getcwd() + wordlist):
            fs = open(os.getcwd() + wordlist, "r")
            for i in fs:
                print(url + "/" + i)
                rq = requests.get(url + "/" + i)
                if rq.status_code == 200:
                    print(">OK".rjust(len(url + "/" + i) + 5, "-"))
                    arr.append(str(url + "/" + i))
                else:
                    print(">404".rjust(len(url + "/" + i) + 5, "-"))
            fs.close()
            print("output".center(100, "-"))
            l = 1
            for i in arr:
                print(l, "> ", i)
                l += 1
        else:
            print(wordlist + " don't exists in the directory.")
    except Exception as e:
        print(e)
