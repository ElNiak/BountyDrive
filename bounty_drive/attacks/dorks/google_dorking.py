#########################################################################################
# Google Dorking and searching functions
#########################################################################################

# Proxy-aware Google search function
import glob
import random
import sys
import re
import concurrent.futures
from termcolor import cprint
from tqdm import tqdm

from attacks.dorks import dorking_config
from utils.app_config import (
    DEFAULT_TOTAL_OUTPUT,
    EXTENSION,
    LANG,
    POTENTIAL_PATHS,
    TOTAL_OUTPUT,
    USER_AGENTS,
)
from utils.proxies import round_robin_proxies
from utils.request_manager import param_converter, start_request
from utils.results_manager import safe_add_result


def google_search_with_proxy(dork_tuple, proxy, category, retries=3, advanced=False):
    try:
        query, extension, category = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""

    base_url = "https://www.google.com/search"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxies = {"http": proxy, "https": proxy}

    full_query = generate_dork_query(query, extension)

    # Threat data as path
    is_json = False
    # url = param_converter(data, url) # TODO
    data = None
    GET, POST = True, False
    params = {
        "client": "ubuntu-sn",
        "channel": "fs",
        "q": full_query,
        # "num": TOTAL_OUTPUT,  # Prevents multiple requests
        # "hl": LANG,
    }

    urls = None
    for _ in range(retries):
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
        )
        if urls:
            return category, urls, full_query
    return category, urls, full_query


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
    if '"' in query:
        if not query.startswith('"'):
            query = '"' + query
        if not query.endswith('"'):
            query = query + '"'

    in_url_query = "inurl:" + query
    in_text_query = "intext:" + query

    query = in_url_query + " | " + in_text_query

    query = query + " | " + "inurl:&"

    # Incorporate subdomain into the search query if specified
    if len(dorking_config.SUBDOMAIN) > 0:
        # Remove any existing site: tag and its value
        query = re.sub(r"site:[^\s]+", "", query)
        to_search = " | ".join(f"site:{domain}" for domain in dorking_config.SUBDOMAIN)
        full_query = f"({to_search}) & ({query})".strip()
    else:
        full_query = f"({query})".strip()

    if extension and len(extension) > 0:
        full_query = full_query + f" & filetype:{extension}"

    return full_query  # Indicate failure after retries


def load_google_dorks_and_search(extensions=None, proxies=None):
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

    # Now, append a proxy to each task
    search_tasks_with_proxy = []
    for task, cat in search_tasks_fill:
        proxy = next(proxy_cycle)
        search_tasks_with_proxy.append({"dork": task, "proxy": proxy, "category": cat})

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_search = {
            executor.submit(
                google_search_with_proxy, task["dork"], task["proxy"], task["category"]
            ): task
            for task in search_tasks_with_proxy
        }
        for future in tqdm(
            concurrent.futures.as_completed(future_to_search),
            total=len(future_to_search),
            desc="Searching for vulnerable website",
            unit="site",
            leave=True,
            position=0,
        ):
            result = future.result()
            if result:
                safe_add_result(result)
