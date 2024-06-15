import os
from urllib.parse import urljoin
import requests

# web_scraper.py
import requests
from bs4 import BeautifulSoup


def fetch_html_content(url, proxy=None, headers=None):
    """
    Fetch the HTML content of a given URL.

    Args:
        url (str): The URL to fetch the content from.

    Returns:
        str: HTML content of the page or None if request fails.
    """
    try:
        response = requests.get(url, proxies=proxy, headers=headers, verify=False)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch the URL: {e}")
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
        script_content = script.string
        if script_content and "window.location" in script_content:
            parts = script_content.split("window.location")
            for part in parts[1:]:
                url_start = part.find("=") + 1
                url_end = part.find(";")
                if url_start > 0 and url_end > 0:
                    js_url = part[url_start:url_end].strip().strip("'\"")
                    link = urljoin(base_url, js_url)
                    links.append(link)

    return links


def scrape_links_from_url(url, proxy=None, headers=None):
    """
    Scrape all potential links and redirections from a given URL.

    Args:
        url (str): The URL to scrape.

    Returns:
        list: List of URLs found in the page.
    """
    html_content = fetch_html_content(url, proxy=proxy, headers=headers)
    if html_content:
        return extract_links(html_content, url)
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
