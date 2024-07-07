import os
import sys
import threading
import concurrent.futures
import time
from urllib.parse import urlparse
from termcolor import cprint
from tqdm import tqdm

from attacks.xss.xss_striker import photon_crawler
from reporting.results_manager import (
    get_links,
    get_processed_crawled,
    save_crawling_query,
    crawling_results,
)
from vpn_proxies.proxies_manager import get_proxies_and_cycle
from scraping.web_scraper import scrape_links_from_url


def launch_crawling_attack(config):
    start_time = time.time()
    website_to_test = get_links(config)
    cprint(
        "\nCrawling/Webscraping for vulnerable website...\n",
        "blue",
        file=sys.stderr,
    )
    if not website_to_test:
        cprint(
            "No websites found matching the dorks. Please adjust your search criteria.",
            "red",
            file=sys.stderr,
        )
    try:
        proxies, proxy_cycle = get_proxies_and_cycle(config)

        if config["do_web_scrap"]:
            # todo MERGE WITH CRAWL
            new_urls = []

            lock = threading.Lock()

            # Now, append a proxy to each task
            number_of_worker = 30  # min(len(proxies)*2, 30)
            search_tasks_with_proxy = []
            for website in website_to_test:
                proxy = next(proxy_cycle)
                search_tasks_with_proxy.append({"website": website, "proxy": proxy})

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=number_of_worker
            ) as executor:
                future_to_search = {
                    executor.submit(
                        scrape_links_from_url, task["website"], task["proxy"]
                    ): task
                    for task in search_tasks_with_proxy
                }
                for website in tqdm(
                    concurrent.futures.as_completed(future_to_search),
                    desc=f"Upating links DB for xss website",
                    unit="site",
                    total=len(future_to_search),
                ):
                    with lock:
                        new_urls_temps = website.result()
                        new_urls += new_urls_temps

            cprint(f"Found {len(new_urls)} new links", color="green", file=sys.stderr)

            # crawl the website for more links TODO

            website_to_test += new_urls

            website_to_test = list(set(website_to_test))
        elif config["do_crawl"]:

            # TODO add the set outside the thread and add al lock
            lock = threading.Lock()
            number_of_worker = 30  # min(len(proxies)*2, 30)
            search_tasks_with_proxy = []

            for website in website_to_test:
                cprint(f"Testing {website} for crawling", color="blue", file=sys.stderr)
                scheme = urlparse(website).scheme
                cprint(
                    "Target scheme: {}".format(scheme),
                    color="blue",
                    file=sys.stderr,
                )
                host = urlparse(website).netloc
                cprint("Target host: {}".format(host), color="blue", file=sys.stderr)
                proxy = next(proxy_cycle)
                search_tasks_with_proxy.append({"website": website, "proxy": proxy})

            forms = []
            domURLs = []
            processed_xss_photon_crawl = get_processed_crawled(config)

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=number_of_worker
            ) as executor:
                future_to_search = {
                    executor.submit(
                        photon_crawler,
                        task["website"],
                        config,
                        task["proxy"],
                        processed_xss_photon_crawl,
                    ): task
                    for task in search_tasks_with_proxy
                }
                try:
                    for website in tqdm(
                        concurrent.futures.as_completed(future_to_search),
                        desc=f"Photon Crawling links DB for xss website",
                        unit="site",
                        total=len(future_to_search),
                    ):
                        with lock:
                            crawling_result = website.result()
                            seedUrl = crawling_result[2]
                            cprint(
                                f"Photon crawling finish for {seedUrl}",
                                color="green",
                                file=sys.stderr,
                            )

                            cprint(
                                f"Forms: {crawling_result[0]}",
                                color="green",
                                file=sys.stderr,
                            )
                            cprint(
                                f"DOM URLs: {crawling_result[1]}",
                                color="green",
                                file=sys.stderr,
                            )
                            forms_temps = crawling_result[0]

                            domURLs_temps = crawling_result[1]

                            difference = abs(len(domURLs) - len(forms))

                            if len(domURLs_temps) > len(forms_temps):
                                for i in range(difference):
                                    forms_temps.append(0)
                            elif len(forms_temps) > len(domURLs_temps):
                                for i in range(difference):
                                    domURLs_temps.append(0)

                            result = (seedUrl, forms_temps, domURLs_temps)

                            crawling_results.append((result, config))

                            domURLs += domURLs_temps
                            forms += forms_temps
                except KeyboardInterrupt:
                    cprint(
                        "Process interrupted by user during crawling attack phase ... Saving results",
                        "red",
                        file=sys.stderr,
                    )
                    end_time = time.time()
                    cprint(
                        "Total time taken: " + str(end_time - start_time),
                        "green",
                        file=sys.stderr,
                    )
                    executor._threads.clear()
                    concurrent.futures.thread._threads_queues.clear()
                    # https://stackoverflow.com/questions/49992329/the-workers-in-threadpoolexecutor-is-not-really-daemon
                    for result, config in crawling_results:
                        save_crawling_query(result, config)
                    # TODO with attacks
                    exit(1)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        cprint(f"{exc_type}, {fname}, {exc_tb.tb_lineno}", "red", file=sys.stderr)
        cprint(f"Error: {e}", color="red", file=sys.stderr)
        end_time = time.time()
        cprint(
            "Total time taken: " + str(end_time - start_time),
            "green",
            file=sys.stderr,
        )
        executor._threads.clear()
        concurrent.futures.thread._threads_queues.clear()
        # https://stackoverflow.com/questions/49992329/the-workers-in-threadpoolexecutor-is-not-really-daemon
        for result, config in crawling_results:
            save_crawling_query(result, config)
    finally:
        end_time = time.time()
        cprint(
            "Total time taken: " + str(end_time - start_time), "green", file=sys.stderr
        )
        cprint(
            f"Total domURLs links: {len(domURLs)}",
            color="green",
            file=sys.stderr,
        )
        cprint(
            f"Total forms links: {len(forms)}",
            color="green",
            file=sys.stderr,
        )
        print(
            "Ending crawling attack phase ... Saving results",
            "red",
            file=sys.stderr,
        )
        concurrent.futures.thread._threads_queues.clear()
        # https://stackoverflow.com/questions/49992329/the-workers-in-threadpoolexecutor-is-not-really-daemon
        for result, config in crawling_results:
            save_crawling_query(result, config)
        # TODO with attacks
        # exit(1)
