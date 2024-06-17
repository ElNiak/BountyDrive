import json
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

from utils.app_config import USER_AGENTS

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    cprint(
        "Selenium is not installed. Please install it using 'pip install selenium'.",
        "red",
        file=sys.stderr,
    )
    sys.exit(1)


class SearchResult:
    def __init__(self, url, title, description):
        self.url = url
        self.title = title
        self.description = description

    def __repr__(self):
        return f"SearchResult(url={self.url}, title={self.title}, description={self.description})"


def parse_google_search_results(proxies, advanced, full_query, response):
    """_summary_

    Args:
        proxies (_type_): _description_
        advanced (_type_): _description_
        full_query (_type_): _description_
        response (_type_): _description_

    Returns:
        _type_: _description_
    """
    urls = []
    soup = BeautifulSoup(response, "html.parser")
    result_block = soup.find_all("div", attrs={"class": "g"})
    cprint(
        f"Potentially {len(result_block)} links ...",
        "yellow",
        file=sys.stderr,
    )
    if len(result_block) == 0:
        cprint(
            f"No results found for parsing of {full_query} with proxy {proxies}\n{response}\nTrying new parsing method",
            "yellow",
            file=sys.stderr,
        )
        # Locate all <a> tags that contain the search results
        for a_tag in soup.find_all("a", href=True):
            # Extract the href attribute
            href = a_tag["href"]
            # Only consider hrefs that start with '/url?'
            if href.startswith("/url?"):
                # Extract the actual URL using regex
                url_match = re.search(r"(https?://[^&]+)", href)
                if url_match:
                    url = url_match.group(0)
                    cprint(f"Checking for url: {url}", color="yellow", file=sys.stderr)
                    # Extract the title (text within <div> with specific class)
                    title_tag = a_tag.find("h3") or a_tag.find(
                        "div", class_="BNeawe vvjwJb AP7Wnd UwRFLe"
                    )
                    title = title_tag.get_text() if title_tag else None
                    if title:
                        cprint(
                            f"Link appended to potential urls: {url}",
                            "green",
                            file=sys.stderr,
                        )
                        urls.append(url)
            else:
                pass
    else:
        for result in result_block:
            # Find link, title, description
            link = result.find("a", href=True)
            title = result.find("h3")
            description_box = result.find("div", {"style": "-webkit-line-clamp:2"})
            if description_box:
                description = description_box.text
                if link and title and description:
                    cprint(
                        f"Link appended to potential urls: {link['href']}",
                        "green",
                        file=sys.stderr,
                    )
                    if advanced:
                        urls.append(SearchResult(link["href"], title.text, description))
                    else:
                        urls.append(link["href"])
    cprint(
        f"Done parsing search results - {len(urls)} potential new links",
        "green",
        file=sys.stderr,
    )
    return urls


def fetch_html_content(url, config, proxy=None, headers=None):
    """
    Fetch the HTML content of a given URL.

    Args:
        url (str): The URL to fetch the content from.

    Returns:
        str: HTML content of the page or None if request fails.
    """
    try:
        cprint(f"Fetching {url}", color="yellow", file=sys.stderr)
        if proxy and "username:password" in proxy:
            print(f"logins :{json.loads(config['nord_vpn_login'])}")
            nord_vpn_user_pass = random.choice(json.loads(config["nord_vpn_login"]))
            proxy = proxy.replace("username", nord_vpn_user_pass[0]).replace(
                "password", nord_vpn_user_pass[1]
            )
            proxies = {"https": proxy}
            secured = True
        else:
            proxies = {"http": proxy, "https": proxy}
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-HackerOne-Research": "elniak",
        }
        response = requests.Session().get(
            url,
            proxies=proxies,
            headers=headers,
            verify=secured,
            allow_redirects=True,
            timeout=config["request_delay"],
        )
        delay = random.uniform(config["current_delay"] - 5, config["current_delay"] + 5)
        time.sleep(delay)  # Wait before retrying
        return response.text
    except requests.exceptions.ProxyError as e:
        cprint(
            f"ProxyError searching for {url} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(config["current_delay"] - 2, config["current_delay"] + 2)
        time.sleep(delay)  # Wait before retrying
        # TODO add backoff timer for delay ?
        return None
    except requests.exceptions.RequestException as e:
        cprint(
            f"RequestException searching for {url} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(config["current_delay"] - 5, config["current_delay"] + 5)
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


def render_js_and_get_text(url, proxy=None):
    """
    Use Selenium to render JavaScript and extract links.

    Args:
        url (str): URL of the page to scrape.

    Returns:
        list: List of absolute URLs found in the rendered HTML.
    """
    cprint(f"Rendering JavaScript for {url}", color="yellow", file=sys.stderr)
    try:
        options = Options()
        options.headless = True
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        # service=Service('/path/to/chromedriver'),
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        html_content = driver.page_source
        driver.quit()
    except Exception as e:
        cprint(f"Error rendering JS for {url}: {e}", color="red", file=sys.stderr)
        # return []
        html_content = ""
    finally:
        return html_content


def render_js_and_extract_links(url, html_content_get, proxy=None):
    """
    Use Selenium to render JavaScript and extract links.

    Args:
        url (str): URL of the page to scrape.

    Returns:
        list: List of absolute URLs found in the rendered HTML.
    """
    cprint(f"Rendering JavaScript for {url}", color="yellow", file=sys.stderr)
    try:
        options = Options()
        options.headless = True
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        # service=Service('/path/to/chromedriver'),
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        html_content = driver.page_source
        driver.quit()
    except Exception as e:
        cprint(f"Error rendering JS for {url}: {e}", color="red", file=sys.stderr)
        # return []
        html_content = ""
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
        return render_js_and_extract_links(url, html_content, proxy=proxy)
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
