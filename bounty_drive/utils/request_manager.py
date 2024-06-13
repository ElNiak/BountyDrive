import json
import re
import sys
import time
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
import requests
from termcolor import cprint

from utils.app_config import CURRENT_DELAY, INITIAL_DELAY, REQUEST_DELAY, WAF_DELAY


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
):
    urls = None
    try:
        if GET:
            cprint(
                f"Searching for GET: {base_url} and parameters {params} ({category} and with proxy {proxies['https']}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.get(
                base_url,
                # data=data[0],
                headers=headers,
                params=params,
                proxies=proxies,
                verify=True,  # TODO add parameter for that
                timeout=REQUEST_DELAY,
            )
        elif is_json:
            cprint(
                f"Searching for POST + JSON:  {base_url}/{full_query} with data {data} ({category} and  with proxy {proxies['https']}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.post(
                base_url,
                json=data[0],
                headers=headers,
                timeout=REQUEST_DELAY,
                verify=True,
                proxies=proxies,
            )
        else:
            cprint(
                f"Searching for POST:  {base_url}/{full_query} with data {data} ({category} and with proxy {proxies['https']}) ...",
                "yellow",
                file=sys.stderr,
            )
            response = requests.post(
                base_url,
                data=data[0],
                headers=headers,
                timeout=REQUEST_DELAY,
                verify=True,
                proxies=proxies,
            )

        # Parse Google response
        if scrap_urls:
            urls = []
            soup = BeautifulSoup(response.text, "html.parser")
            result_block = soup.find_all("div", attrs={"class": "g"})
            for result in result_block:
                # Find link, title, description
                link = result.find("a", href=True)
                title = result.find("h3")
                description_box = result.find("div", {"style": "-webkit-line-clamp:2"})
                if description_box:
                    description = description_box.text
                    if link and title and description:
                        cprint(
                            f"Link appended to potential urls: {link}",
                            "yellow",
                            file=sys.stderr,
                        )
                        if advanced:
                            urls.append(
                                SearchResult(link["href"], title.text, description)
                            )
                        else:
                            urls.append(link["href"])

        # Placeholder for URL extraction logic
        return urls  # Return the category and a placeholder result
    except requests.exceptions.ProtocolError:
        cprint(
            "WAF is dropping suspicious requests. Scanning will continue after 10 minutes.",
            color="red",
            file=sys.stderr,
        )
        time.sleep(WAF_DELAY)
    except requests.exceptions.RequestException as e:
        cprint(
            f"Error searching for {full_query} with proxy {proxies['https']}: {e}",
            "red",
            file=sys.stderr,
        )
        time.sleep(CURRENT_DELAY)  # Wait before retrying
        # TODO add backoff timer for delay ?
    finally:
        return urls
