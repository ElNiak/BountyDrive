#########################################################################################
# Google Dorking and searching functions
#########################################################################################

# Proxy-aware Google search function
import glob
import random
import threading
import concurrent.futures
from termcolor import cprint
from tqdm import tqdm

from bounty_drive.attacks.dorks.dorking_config import SUBDOMAIN
from bounty_drive.utils.app_config import DEFAULT_TOTAL_OUTPUT, LANG, USER_AGENTS
from bounty_drive.utils.proxies import round_robin_proxies
from bounty_drive.utils.request_manager import param_converter
from bounty_drive.utils.results_manager import safe_add_result


def google_search_with_proxy(
    dork_tuple, proxy, category, retries=3, advanced=False, waf=False
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

    # TODO
    if "?" in query:
        # Threat data as path
        is_json = False
        url = param_converter(data, url)
        data = []
        GET, POST = True, False
        params = {
            "q": full_query,
            "num": DEFAULT_TOTAL_OUTPUT + 2,  # Prevents multiple requests
            "hl": LANG,
        }
    else:
        # Threat data as JSON
        is_json = True
        headers["Content-type"] = "application/json"
        data = param_converter(data)
        params = {}

    urls = []
    for _ in range(retries):
        # The code you provided is not valid Python code. It seems like you have written some comments
        # but there is no actual code present. If you have a specific question or need help with
        # Python code, please provide the code snippet so I can assist you better.
        urls = start_request(
            proxies=proxies,
            advanced=advanced,
            waf=waf,
            GET=GET,
            url=url,
            data=data,
            headers=headers,
            params=params,
            base_url=base_url,
            full_query=full_query,
            is_json=is_json,
            category=category,
        )

    if urls:
        return category, urls
    return category, None  # Indicate failure after retries


def load_google_dorks_and_search(proxies=None):
    dork_files = glob.glob("dorks/google/*")
    proxy_cycle = round_robin_proxies(proxies)

    websites_sqli = set()
    websites_xss = set()
    websites_api = set()
    websites_web = set()
    websites_secret = set()
    websites_dlphp = set()
    websites_backup = set()
    websites_git = set()

    lock = threading.Lock()  # To ensure thread-safe operations on sets

    search_tasks = []

    search_tasks_sqli = []
    search_tasks_xss = []
    search_tasks_api = []
    search_tasks_web = []
    search_tasks_secret = []
    search_tasks_dlphp = []
    search_tasks_backup = []

    for dork_file in dork_files:
        if "sql" in dork_file.lower():
            category = "sqli"
        elif "xss" in dork_file.lower():
            category = "xss"
        elif "api" in dork_file.lower():
            category = "api"
        elif "web" in dork_file.lower():
            category = "web"
        elif "secret" in dork_file.lower():
            category = "secret"
        elif "download-php" in dork_file.lower():
            category = "dlphp"
        elif "backup" in dork_file.lower():
            category = "backup"
        else:
            category = "other"
        with open(dork_file, "r") as file:
            dorks = [
                (line.strip(), extension, category) for line in file if line.strip()
            ]

        # Separate tasks by category before shuffling
        if category == "sqli":
            search_tasks_sqli.extend(dorks)
        elif category == "xss":
            search_tasks_xss.extend(dorks)
        elif category == "api":
            search_tasks_api.extend(dorks)
        elif category == "web":
            search_tasks_web.extend(dorks)
        elif category == "secret":
            search_tasks_secret.extend(dorks)
        elif category == "dlphp":
            search_tasks_dlphp.extend(dorks)
        elif category == "backup":
            search_tasks_backup.extend(dorks)

    # Now shuffle the dorks within each category
    random.shuffle(search_tasks_sqli)
    random.shuffle(search_tasks_xss)
    random.shuffle(search_tasks_api)
    random.shuffle(search_tasks_web)
    random.shuffle(search_tasks_secret)
    random.shuffle(search_tasks_dlphp)
    random.shuffle(search_tasks_backup)

    # Combine the tasks back together, maintaining category grouping
    search_tasks = (
        search_tasks_sqli
        + search_tasks_xss
        + search_tasks_api
        + search_tasks_web
        + search_tasks_secret
        + search_tasks_dlphp
        + search_tasks_backup
    )
    cprint(f"Total number of dorks: {len(search_tasks)}", "yellow", file=sys.stderr)
    search_tasks_with_proxy = []
    # Now, append a proxy to each task
    for task in search_tasks:
        dork, extension, category = task
        proxy = next(proxy_cycle)
        search_tasks_with_proxy.append((dork, proxy, category))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_search = {
            executor.submit(google_search_with_proxy, task[0], task[1], task[2]): task
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
                    safe_add_result(
                        result,
                        websites_sqli,
                        websites_xss,
                        websites_web,
                        websites_api,
                        websites_secret,
                        websites_dlphp,
                        websites_backup,
                        websites_git,
                    )

    return (
        proxies,
        list(websites_sqli),
        list(websites_xss),
        list(websites_api),
        list(websites_web),
        list(websites_secret),
        list(websites_dlphp),
        list(websites_backup),
        list(websites_git),
    )
