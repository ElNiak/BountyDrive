import json
import random
import re
import sys
import time
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
import requests
from termcolor import cprint

from utils.app_config import CURRENT_DELAY, LONG_DELAY, REQUEST_DELAY, WAF_DELAY

from fp.fp import FreeProxyException


class SearchResult:
    def __init__(self, url, title, description):
        self.url = url
        self.title = title
        self.description = description

    def __repr__(self):
        return f"SearchResult(url={self.url}, title={self.title}, description={self.description})"


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


def inject_params(url, payload):
    """
    Injects the payload in the parameters and returns a set
    """
    injected_url = set()
    temp_payload = (
        payload.replace("\\n", "$").replace("\\t", "@").replace("\\r", "!")
    )  # saves the payload from the removal of \\n, \\t and \\r
    injected = re.sub(r"=[^?\|&]*", "=" + str(temp_payload), str(url))
    final_payload = injected.replace("$", "\\n").replace("@", "\\t").replace("!", "\\r")
    injected_url.add(final_payload)

    return injected_url


def param_converter(data, url=False):
    if "str" in str(type(data)):
        if url:
            dictized = {}
            parts = data.split("/")[3:]
            for part in parts:
                dictized[part] = part
            return dictized
        else:
            return json.loads(data)
    else:
        if url:
            url = urlparse(url).scheme + "://" + urlparse(url).netloc
            for part in list(data.values()):
                url += "/" + part
            return url
        else:
            return json.dumps(data)


def start_request(
    proxies,
    advanced=False,
    is_json=False,
    GET=False,
    data=None,
    headers=None,
    params=None,
    base_url=None,
    full_query=None,
    category=None,
    scrap_urls=False,
    retry_no=0,
    secured=False,
):
    urls = None
    try:
        if GET:
            cprint(
                f"Searching for GET (n° {retry_no}): {base_url} & parameters {params} & headers {headers} - ({category} and with proxy {proxies}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.Session().get(
                base_url,
                # data=data[0],
                headers=headers,
                params=params,
                allow_redirects=True,
                proxies=proxies,
                # cookies = {'CONSENT' : 'YES+'},
                cookies={
                    "CONSENT": "PENDING+987",
                    "SOCS": "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg",
                },  # FOR EU USERS -> ANNOYING to parse
                verify=secured,  # TODO add parameter for that
                timeout=REQUEST_DELAY,
            )
        elif is_json:
            cprint(
                f"Searching for POST + JSON (n° {retry_no}):  {base_url}/{full_query}  & data {data} & headers {headers} - ({category} and  with proxy {proxies}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.Session().post(
                base_url,
                json=data[0],
                headers=headers,
                timeout=REQUEST_DELAY,
                verify=secured,
                cookies={
                    "CONSENT": "PENDING+987",
                    "SOCS": "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg",
                },  # FOR EU USERS
                proxies=proxies,
            )
        else:
            cprint(
                f"Searching for POST (n° {retry_no}):  {base_url}/{full_query}  & data {data} & headers {headers} - ({category} and with proxy {proxies}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.Session().post(
                base_url,
                data=data[0],
                headers=headers,
                timeout=REQUEST_DELAY,
                verify=secured,
                cookies={
                    "CONSENT": "PENDING+987",
                    "SOCS": "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg",
                },  # FOR EU USERS
                proxies=proxies,
            )

        # Parse Google response
        if response.status_code != 200:
            cprint(
                f"Error in request ... - status code = {response.status_code}",
                color="red",
                file=sys.stderr,
            )
            if response.status_code == 429:
                # delay = random.uniform(LONG_DELAY-5, LONG_DELAY+5)
                # time.sleep(delay)  # Wait before retrying
                retry_after = int(response.headers.get("Retry-After", 60))
                cprint(
                    f"Retry after {retry_after} secs ...",
                    "red",
                    file=sys.stderr,
                )
                time.sleep(retry_after)
            elif response.status_code == 403:
                cprint(
                    "WAF is dropping suspicious requests. Scanning will continue after 10 minutes.",
                    color="red",
                    file=sys.stderr,
                )
                time.sleep(WAF_DELAY)
        else:
            if "did not match any documents" in response.text:
                cprint(
                    f"No results found for {full_query} with proxy {proxies}",
                    "yellow",
                    file=sys.stderr,
                )
            elif scrap_urls:
                urls = []
                soup = BeautifulSoup(response.text, "html.parser")
                result_block = soup.find_all("div", attrs={"class": "g"})
                cprint(
                    f"Potentially {len(result_block)} links ...",
                    "yellow",
                    file=sys.stderr,
                )
                if len(result_block) == 0:
                    cprint(
                        f"No results found for {full_query} with proxy {proxies}\n{response.text}\nTrying new parsing method",
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
                                print(url)
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
                    for result in result_block:
                        # Find link, title, description
                        link = result.find("a", href=True)
                        title = result.find("h3")
                        description_box = result.find(
                            "div", {"style": "-webkit-line-clamp:2"}
                        )
                        if description_box:
                            description = description_box.text
                            if link and title and description:
                                cprint(
                                    f"Link appended to potential urls: {link['href']}",
                                    "green",
                                    file=sys.stderr,
                                )
                                if advanced:
                                    urls.append(
                                        SearchResult(
                                            link["href"], title.text, description
                                        )
                                    )
                                else:
                                    urls.append(link["href"])

            else:
                cprint(
                    f"No scraping  ...",
                    "yellow",
                    file=sys.stderr,
                )

        # Placeholder for URL extraction logic
        delay = random.uniform(CURRENT_DELAY - 5, CURRENT_DELAY + 5)
        time.sleep(delay)  # Wait before retrying
        return urls  # Return the category and a placeholder result
    except requests.exceptions.ProxyError as e:
        cprint(
            f"ProxyError searching for {full_query} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(CURRENT_DELAY - 2, CURRENT_DELAY + 2)
        time.sleep(delay)  # Wait before retrying
        # TODO add backoff timer for delay ?
        return urls
    except requests.exceptions.RequestException as e:
        cprint(
            f"RequestException searching for {full_query} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(CURRENT_DELAY - 2, CURRENT_DELAY + 2)
        time.sleep(delay)  # Wait before retrying
        # TODO add backoff timer for delay ?
        return urls
    except FreeProxyException as e:
        cprint(
            f"FreeProxyException: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(CURRENT_DELAY - 2, CURRENT_DELAY + 2)
        time.sleep(delay)  # Wait before retrying
        # TODO add backoff timer for delay ?
        return urls
    # finally:
    #     return urls
