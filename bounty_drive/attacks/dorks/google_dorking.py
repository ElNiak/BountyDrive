#########################################################################################
# Google Dorking and searching functions
#########################################################################################

# Proxy-aware Google search function
import glob
import random
import sys
import threading
import concurrent.futures
from termcolor import cprint
from tqdm import tqdm

from attacks.dorks.dorking_config import SUBDOMAIN
from utils.app_config import DEFAULT_TOTAL_OUTPUT, LANG, TOTAL_OUTPUT, USER_AGENTS
from utils.proxies import round_robin_proxies
from utils.request_manager import param_converter, start_request
from utils.results_manager import safe_add_result


def google_search_with_proxy(
    dork_tuple, proxy, category, retries=3 , advanced=False
):
    try:
        query, extension = dork_tuple
    except ValueError:
        query = dork_tuple
        extension = ""

    base_url = "https://www.google.com/search"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxies = {"http": proxy, "https": proxy}

    # Incorporate subdomain into the search query if specified
    if SUBDOMAIN:
        full_query = f"site:{SUBDOMAIN} {query} {extension}".strip()
    else:
        full_query = f"{query} {extension}".strip()


    # Threat data as path
    is_json = False
    # url = param_converter(data, url) # TODO
    data = []
    GET, POST = True, False
    params = {
        "q": full_query,
        "num": TOTAL_OUTPUT + 2,  # Prevents multiple requests
        "hl": LANG,
    }

    urls = []
    for _ in range(retries):
        # The code you provided is not valid Python code. It seems like you have written some comments
        # but there is no actual code present. If you have a specific question or need help with
        # Python code, please provide the code snippet so I can assist you better.
        urls = start_request(
            proxies=proxies,
            advanced=advanced,
            GET=GET,
            data=full_query,
            headers=headers,
            params=params,
            base_url=base_url,
            full_query=full_query,
            is_json=is_json,
            category=category,
            get_urls=True,
        )
        if urls:
            break

    if urls:
        return category, urls
    return category, None  # Indicate failure after retries


def load_google_dorks_and_search(extensions=None, proxies=None):
    dork_files = glob.glob("dorks/google/*")
    proxy_cycle = round_robin_proxies(proxies)

    lock = threading.Lock()  # To ensure thread-safe operations on sets

    search_tasks = {
        "sqli": [],
        "xss": [],
        "api": [],
        "web": [],
        "secret": [],
        "dlphp": [],
        "backup": [],
    }

    for dork_file in dork_files:
        category_mapping = search_tasks.keys()
        category = "other"
        for cat in category_mapping:
            if cat in dork_file.lower():
                category = cat
                break

        with open(dork_file, "r") as file:
            dorks = [
                (line.strip(), extension, category) for line in file if line.strip()
            ]

        # Separate tasks by category before shuffling
        search_tasks[category] = dorks
    search_tasks_fill = []
    # Now shuffle the dorks within each category
    for cat in search_tasks:
        random.shuffle(search_tasks[cat])
        search_tasks_fill.append((search_tasks[cat],cat))

    cprint(f"Total number of dorks: {len(search_tasks)}", "yellow", file=sys.stderr)

    # Now, append a proxy to each task
    search_tasks_with_proxy = []
    for task, cat in search_tasks_fill:
        proxy = next(proxy_cycle)
        search_tasks_with_proxy.append(
            {"dork": task, "proxy": proxy, "category": cat}
        )

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
        ):
            result = future.result()
            if result:
                with lock:
                    safe_add_result(result)
