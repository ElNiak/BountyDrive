import json
import random
import re
import sys
import time
from urllib.parse import parse_qs, urlparse

import requests
from termcolor import cprint


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
            # url = urlparse(url).scheme + "://" + urlparse(url).netloc
            url = url + "/?"
            for key in data.keys():
                url += key + str(data[key]) + "&"
            return url
        else:
            return json.dumps(data)


def start_request(
    proxies,
    config,
    is_json=False,
    GET=False,
    data=None,
    headers=None,
    params=None,
    base_url=None,
    secured=False,
    cookies=None,
    session=None,
):
    if session:
        requester = session
    else:
        requester = requests
    try:
        if GET:
            response = requester.get(
                base_url,
                headers=headers,
                params=params,
                allow_redirects=True,
                proxies=proxies,
                # cookies = {'CONSENT' : 'YES+'},
                cookies=cookies,  # FOR EU USERS -> ANNOYING to parse
                verify=secured,  # TODO add parameter for that
                timeout=config["request_delay"],
            )
        elif is_json:
            response = requester.post(
                base_url,
                json=data[0],
                headers=headers,
                timeout=config["request_delay"],
                verify=secured,
                cookies=cookies,  # FOR EU USERS
                proxies=proxies,
            )
        else:
            response = requester.post(
                base_url,
                data=data[0],
                headers=headers,
                timeout=config["request_delay"],
                verify=secured,
                cookies=cookies,  # FOR EU USERS
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
                time.sleep(config["waf_delay"])
            else:
                cprint(
                    f"Error in request ... - status code = {response.status_code}",
                    color="red",
                    file=sys.stderr,
                )
                delay = random.uniform(
                    config["current_delay"] - 5, config["current_delay"] + 5
                )
                time.sleep(delay)  # Wait before retrying
            return None
        elif "did not match any documents" in response.text:
            cprint(
                f"No results found for {params['q']} with proxy {proxies} \n {response.text}",
                "yellow",
                file=sys.stderr,
            )
            delay = random.uniform(
                config["current_delay"] - 5, config["current_delay"] + 5
            )
            time.sleep(delay)  # Wait before retrying
            return None
        # Placeholder for URL extraction logic
        cprint("Request successful - 200", "green", file=sys.stderr)
        delay = random.uniform(config["current_delay"] - 5, config["current_delay"] + 5)
        time.sleep(delay)  # Wait before retrying
        return response  # Return the category and a placeholder result
    except requests.exceptions.ProxyError as e:
        cprint(
            f"ProxyError searching for {params['q']} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(config["current_delay"] - 2, config["current_delay"] + 2)
        time.sleep(delay)  # Wait before retrying
        return None
    except requests.exceptions.RequestException as e:
        cprint(
            f"RequestException searching for {params['q']} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        delay = random.uniform(config["current_delay"] - 2, config["current_delay"] + 2)
        time.sleep(delay)  # Wait before retrying
        return None
