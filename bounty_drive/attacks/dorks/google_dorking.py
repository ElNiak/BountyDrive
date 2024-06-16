#########################################################################################
# Google Dorking and searching functions
#########################################################################################

# Proxy-aware Google search function
import glob
import random
import threading
import time
from tqdm import tqdm
import sys
import re
import concurrent.futures
from termcolor import cprint

from attacks.dorks.dorking_config import dorking_config
from utils.app_config import (
    DEFAULT_TOTAL_OUTPUT,
    EXTENSION,
    LANG,
    POTENTIAL_PATHS,
    TOTAL_OUTPUT,
    USER_AGENTS,
    use_nordvpn,
)
from utils.nord_vpn_config import *
from utils.proxies import round_robin_proxies
from utils.request_manager import param_converter, start_request
from utils.results_manager import safe_add_result

from nordvpn_switcher.nordvpn_switch import initialize_VPN, rotate_VPN, terminate_VPN


def change_vpn(time=300):
    rotate_VPN()
    time.sleep(time)


def google_search_with_proxy(
    dork_tuple,
    proxy,
    category,
    retries=1,
    advanced=False,
    total_output=TOTAL_OUTPUT,
    generated_dorks=True,
    secured=False,
):
    try:
        query, extension, category = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""

    base_url = "https://www.google.com/search"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
    }

    if "username:password" in proxy:
        nord_vpn_user_pass = random.choice(nord_vpn_login)
        proxy = proxy.replace("username", nord_vpn_user_pass[0]).replace(
            "password", nord_vpn_user_pass[1]
        )
        proxies = {"https": proxy}
        secured = True
    else:
        proxies = {"http": proxy, "https": proxy}

    if generated_dorks:
        full_query = generate_dork_query(query, extension)
    else:
        full_query = query

    if isinstance(full_query, list):
        for q in full_query:
            # Threat data as path
            is_json = False
            # url = param_converter(data, url) # TODO
            data = None
            GET, POST = True, False
            params = {
                # "client": "ubuntu-sn",
                # "channel": "fs",
                "q": q,
                "num": total_output,  # Prevents multiple requests
                "hl": LANG,
            }

            urls = None
            for retry_no in range(retries):
                urls = start_request(
                    proxies=proxies,
                    advanced=advanced,
                    GET=GET,
                    data=data,
                    headers=headers,
                    params=params,
                    base_url=base_url,
                    full_query=q,
                    is_json=is_json,
                    category=category,
                    scrap_urls=True,
                    retry_no=retry_no,
                    secured=secured,
                )
                if urls:
                    result = category, urls, q
                    safe_add_result(result)
        return
    else:
        # Threat data as path
        is_json = False
        # url = param_converter(data, url) # TODO
        data = None
        GET, POST = True, False
        params = {
            # "client": "ubuntu-sn",
            # "channel": "fs",
            "q": full_query,
            "num": total_output,  # Prevents multiple requests
            "hl": LANG,
        }

        urls = None
        for retry_no in range(retries):
            urls = start_request(
                proxies=proxies,
                advanced=advanced,
                GET=GET,
                data=data,
                headers=headers,
                params=params,
                base_url=base_url,
                full_query=full_query,
                is_json=is_json,
                category=category,
                scrap_urls=True,
                retry_no=retry_no,
                secured=secured,
            )
            if urls:
                result = category, urls, full_query
                safe_add_result(result)
                return

    result = category, urls, full_query
    safe_add_result(result)
    return


google_dork_tags = [
    "site:",  # Search within a specific site or domain
    "intitle:",  # Search for pages with a specific word in the title
    "inurl:",  # Search for pages with a specific word in the URL
    "intext:",  # Search for pages with a specific word in the text
    "filetype:",  # Search for files of a specific type (e.g., PDF, DOC)
    "ext:",  # Similar to filetype:, search for files with a specific extension
    "link:",  # Search for pages that link to a specific URL
    "cache:",  # Display Google's cached version of a page
    "related:",  # Find sites related to a given URL
    "info:",  # Show information about a specific URL
    "define:",  # Provide definitions for words
    "insubject:",  # Search for pages with a specific word in the subject (used in Google Groups)
    "daterange:",  # Search within a specific date range (using Julian dates)
    "allintitle:",  # Search for pages with all specified words in the title
    "allinurl:",  # Search for pages with all specified words in the URL
    "allintext:",  # Search for pages with all specified words in the text
    "allinanchor:",  # Search for pages with all specified words in the anchor text
    "author:",  # Search for articles written by a specific author (used in Google Groups)
    "group:",  # Search within a specific Google Group (used in Google Groups)
    "numrange:",  # Search within a specific number range
    "movie:",  # Search for information about a specific movie
    "map:",  # Search for maps
    "weather:",  # Get weather information
    "stocks:",  # Get stock information
    "phonebook:",  # Search for phonebook listings
    "book:",  # Search for books
    "safesearch:",  # Enable or disable safe search
    "blogurl:",  # Search for blogs at a specific URL
    "location:",  # Search for pages related to a specific location
    "before:",  # Search for pages before a specific date
    "after:",  # Search for pages after a specific date
]


def generate_dork_query(query, extension):
    # Clean up the query by removing existing inurl: and intext: tags
    for tag in ["inurl:", "intext:"]:
        query = query.replace(tag, "")

    # Ensure the query is properly enclosed in quotes if it contains quotes
    # if '"' in query:
    if not query.startswith('"'):
        query = '"' + query
    if not query.endswith('"'):
        query = query + '"'

    in_url_query = "inurl:" + query
    in_text_query = "intext:" + query

    query = in_url_query + " | " + in_text_query

    query = query + " | "  # + "inurl:&"

    # Incorporate subdomain into the search query if specified
    if len(dorking_config.SUBDOMAIN) > 0:
        # Remove any existing site: tag and its value
        full_query = []
        query = re.sub(r"site:[^\s]+", "", query)
        for domain in dorking_config.SUBDOMAIN:
            to_search = f"site:{domain}"
        full_query.append(f"({to_search}) & ({query})".strip())
    else:
        full_query = f"({query})".strip()

    if extension and len(extension) > 0:
        if isinstance(extension, full_query):
            full_query_copy = []
            for q in full_query:
                q = q + f" & filetype:{q}"
                full_query_copy.append(q)
            full_query = full_query_copy
        else:
            full_query = full_query + f" & filetype:{extension}"

    return full_query  # Indicate failure after retries


def load_google_dorks_and_search(extensions=None, proxies=None):
    if proxies and len(proxies) < 1:
        cprint(
            f"Using proxies -> you should have at least one UP",
            "red",
            file=sys.stderr,
        )
        exit()

    proxy_cycle = round_robin_proxies(proxies)

    search_tasks = {}
    for cate in POTENTIAL_PATHS.keys():
        search_tasks[cate] = []

    category_mapping = search_tasks.keys()
    for category in category_mapping:
        dork_files = glob.glob(f"attacks/dorks/google/{category}/*.txt", recursive=True)
        for dork_file in dork_files:
            with open(dork_file, "r") as file:
                lines = file.readlines()
                dorks = [(line.strip(), EXTENSION, category) for line in lines]
            # Separate tasks by category before shuffling
            # if len(search_tasks[category]) == 0:
            search_tasks[category] += dorks
            # else:
            #     search_tasks[category][0][0].append(dorks[0][0]) # TODO cla

    # Now shuffle the dorks within each category
    search_tasks_fill = []
    for cat in search_tasks:
        random.shuffle(search_tasks[cat])
        for elem in search_tasks[cat]:
            search_tasks_fill.append((elem, cat))

    cprint(
        f"Total number of dorks: {len(search_tasks_fill)}", "yellow", file=sys.stderr
    )

    if use_nordvpn:
        thread = threading.Thread(target=change_vpn)
        thread.start()

    # Now, append a proxy to each task
    number_of_worker = min(len(proxies), 30)  # /2
    cprint(f"Number of workers: {number_of_worker}", "yellow", file=sys.stderr)
    search_tasks_with_proxy = []
    for task, cat in search_tasks_fill:
        proxy = next(proxy_cycle)
        search_tasks_with_proxy.append({"dork": task, "proxy": proxy, "category": cat})

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=number_of_worker
    ) as executor:
        future_to_search = {
            executor.submit(
                google_search_with_proxy, task["dork"], task["proxy"], task["category"]
            ): task
            for task in search_tasks_with_proxy
        }
        for future in tqdm(
            concurrent.futures.as_completed(future_to_search),
            total=len(future_to_search)
            * (
                1
                if len(dorking_config.SUBDOMAIN) == 0
                else len(dorking_config.SUBDOMAIN)
            ),
            desc="Searching for vulnerable website",
            unit="site",
            # leave=True,
            # position=0,
        ):
            future.result()
