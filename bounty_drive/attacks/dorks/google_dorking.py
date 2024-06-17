#########################################################################################
# Google Dorking and searching functions
#########################################################################################

# Proxy-aware Google search function
import glob
import random
import threading
import requests
from tqdm import tqdm
import sys
import re
import concurrent.futures
from termcolor import cprint

from utils.app_config import (
    USER_AGENTS,
)

from utils.web_scraper import parse_google_search_results, render_js_and_get_text

from utils.proxies_manager import prepare_proxies, round_robin_proxies
from utils.request_manager import param_converter, start_request
from utils.results_manager import get_processed_dorks, safe_add_result

dork_id_lock = threading.Lock()


def google_search_with_proxy(
    dork_query,
    proxy,
    category,
    config,
    domain,
    retries=1,
    advanced=False,
    dork_id=0,
):

    if not config:
        raise Exception("Config file should be provided")

    proxies = prepare_proxies(proxy, config)

    full_query = generate_dork_query(dork_query, config, domain)

    params = prepare_params(config)

    dork_id = perform_searches(
        full_query,
        proxies,
        category,
        params,
        retries,
        config,
        advanced,
        dork_id,
        use_session=not (proxy == None),
    )

    return dork_id


def prepare_params(config):
    return {
        "client": "ubuntu-sn",
        "channel": "fs",
        "num": config["total_output"],
        "hl": config["lang"],
    }


def perform_searches(
    full_query,
    proxies,
    category,
    params,
    retries,
    config,
    advanced,
    dork_id,
    use_session,
):

    params["q"] = full_query
    dork_id = execute_search_with_retries(
        full_query,
        proxies,
        category,
        params,
        retries,
        config,
        advanced,
        dork_id,
        use_session=use_session,
    )

    return dork_id


def execute_search_with_retries(
    query,
    proxies,
    category,
    params,
    retries,
    config,
    advanced,
    dork_id,
    use_session=False,
):
    base_url = "https://www.google.com/search"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for retry_no in range(retries):
        if use_session:
            cprint(
                f"Searching for GET - Session (n° {retry_no}): {base_url} \n\t - parameters {params} \n\t - headers {headers} \n\t - {category} - with proxy {proxies} ...",
                "yellow",
                file=sys.stderr,
            )
            with requests.Session() as session:
                response = start_request(
                    config=config,
                    proxies=proxies,
                    base_url=base_url,
                    GET=True,
                    headers=headers,
                    params=params,
                    is_json=False,
                    secured=True if "socks" in proxies["https"] else False,
                    session=session,
                    cookies={
                        "CONSENT": "PENDING+987",
                        "SOCS": "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg",
                    },
                )
        else:
            cprint(
                f"Searching for GET (n° {retry_no}): {base_url} \n\t - parameters {params} \n\t - headers {headers} \n\t - {category} - with proxy {proxies} ...",
                "yellow",
                file=sys.stderr,
            )
            response = start_request(
                config=config,
                proxies=proxies,
                base_url=base_url,
                GET=True,
                headers=headers,
                params=params,
                is_json=False,
                secured=True if "socks" in proxies["https"] else False,
                cookies={
                    "CONSENT": "PENDING+987",
                    "SOCS": "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg",
                },
            )
        if response:
            urls = parse_google_search_results(proxies, advanced, query, response.text)
            if not urls or len(urls) == 0:
                cprint(
                    f"Parsing for google search failed for {query} - retrying with selenium...",
                    "red",
                    file=sys.stderr,
                )
                html_content = render_js_and_get_text(
                    param_converter(params, url=base_url)
                )
                urls = parse_google_search_results(
                    proxies, advanced, query, html_content
                )
            result = dork_id, category, urls, query
            safe_add_result(result, config)
            with dork_id_lock:
                dork_id += 1
    # TODO to be faster also record non functionnal dork
    return dork_id


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


def generate_dork_query(query, config, domain):
    # Clean up the query by removing existing inurl: and intext: tags
    if len(query) > 0:
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

        query = query  # + " | "  # + "inurl:&"

    # Incorporate subdomain into the search query if specified
    if domain:
        # Remove any existing site: tag and its value
        full_query = []
        query = re.sub(r"site:[^\s]+", "", query)
        to_search = f"site:{domain}"
        if len(query) > 0:
            full_query = f"({to_search}) & ({query})".strip()
        else:
            full_query = f"({to_search})".strip()
    else:
        full_query = f"({query})".strip()

    if config["extension"] and len(config["extension"]) > 0:
        full_query = full_query + f" & filetype:{config['extension']}"

    return full_query  # Indicate failure after retries


def filter_search_tasks(search_tasks, processed_dorks):
    """
    Filters out the already processed dorks from search tasks.
    """
    filtered_tasks = {}
    for category, dorks in search_tasks.items():
        filtered_tasks[category] = [
            dork for dork in dorks if dork not in processed_dorks
        ]
    return filtered_tasks


def load_google_dorks_and_search(config, categories):
    proxies, proxy_cycle = get_proxies_and_cycle(config)

    search_tasks = {}

    for category in categories:
        search_tasks[category] = []
        dork_files = glob.glob(f"attacks/dorks/google/{category}/*.txt", recursive=True)
        for dork_file in dork_files:
            with open(dork_file, "r") as file:
                lines = file.readlines()
                dorks = [line.strip() for line in lines]
            search_tasks[category] += dorks

    cprint(
        f"Total number of dorks: {sum([len(search_tasks[task]) for task in search_tasks])}",
        "yellow",
        file=sys.stderr,
    )
    processed_dorks = get_processed_dorks(config)
    search_tasks = filter_search_tasks(search_tasks, processed_dorks)
    cprint(
        f"Number of dorks to process: {sum([len(search_tasks[task]) for task in search_tasks])}",
        "yellow",
        file=sys.stderr,
    )

    if not search_tasks:
        cprint(f"No dorks to process.", "red", file=sys.stderr)
        return

    if config["use_vpn"]:
        raise NotImplementedError(
            "VPN is not supported in this version - Error in library"
        )
        thread = threading.Thread(target=change_vpn)
        thread.start()

    number_of_worker = min(len(proxies), 30)
    cprint(f"Number of workers: {number_of_worker}", "yellow", file=sys.stderr)

    search_tasks_with_proxy = []
    for task in search_tasks:
        for domain in config["subdomain"]:
            for dork in search_tasks[task]:
                proxy = next(proxy_cycle)
                search_tasks_with_proxy.append(
                    {"dork": dork, "proxy": proxy, "category": task, "domain": domain}
                )
    cprint(
        f"Total number of dorks: {len(search_tasks_with_proxy)}",
        "yellow",
        file=sys.stderr,
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=number_of_worker
    ) as executor:
        future_to_search = {
            executor.submit(
                google_search_with_proxy,
                task["dork"],
                task["proxy"],
                task["category"],
                config,
                task["domain"],
            ): task
            for task in search_tasks_with_proxy
        }
        for future in tqdm(
            concurrent.futures.as_completed(future_to_search),
            total=len(future_to_search),
            desc="Searching for vulnerable website",
            unit="site",
        ):
            # task = future_to_search[future]
            # try:
            future.result()


def get_proxies_and_cycle(config):
    proxies = config["proxies"]
    if config["use_proxy"] and len(proxies) == 0:
        cprint(
            f"Using proxies -> you should have at least one UP",
            "red",
            file=sys.stderr,
        )
        exit()

    if not config["use_proxy"]:
        proxies = [None]

    proxy_cycle = round_robin_proxies(proxies)
    return proxies, proxy_cycle
    # update_csv(config["experiment_file_path"], task, success=True)
    # except Exception as e:
    #     cprint(f"Error processing {task['dork']}: {e}", "red", file=sys.stderr)
    #     # update_csv(config["experiment_file_path"], task, success=False)
