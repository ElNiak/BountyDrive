import sys
import threading
import concurrent.futures
from urllib.parse import urlparse
from termcolor import cprint
import tqdm

from attacks.xss.xss_striker import photon_crawler
from reporting.results_manager import (
    get_processed_crawled,
    save_crawling_query,
    crawling_results,
)
from vpn_proxies.proxies_manager import get_proxies_and_cycle
from scraping.web_scraper import scrape_links_from_url


def launch_crawling_attack(config, website_to_test):
    try:
        proxies, proxy_cycle = get_proxies_and_cycle(config)

        if config["do_web_scrap"]:
            # todo MERGE WITH CRAWL
            new_urls = []

            lock = threading.Lock()

            # Now, append a proxy to each task
            number_of_worker = len(proxies)
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
            lock = threading.Lock()
            number_of_worker = len(proxies)
            search_tasks_with_proxy = []

            for website in website_to_test:
                cprint(
                    f"Testing {website} for crawling", color="yellow", file=sys.stderr
                )
                scheme = urlparse(website).scheme
                cprint(
                    "Target scheme: {}".format(scheme),
                    color="yellow",
                    file=sys.stderr,
                )
                host = urlparse(website).netloc

                main_url = scheme + "://" + host

                cprint("Target host: {}".format(host), color="yellow", file=sys.stderr)

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
                for website in tqdm(
                    concurrent.futures.as_completed(future_to_search),
                    desc=f"Photon Crawling links DB for xss website",
                    unit="site",
                    total=len(future_to_search),
                ):
                    with lock:
                        crawling_result = website.result()
                        seedUrl = website["website"]

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
                        forms_temps = list(set(crawling_result[0]))

                        domURLs_temps = list(set(list(crawling_result[1])))

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
    except KeyboardInterrupt:
        cprint(
            "Process interrupted by user during crawling attack phase ... Saving results",
            "red",
            file=sys.stderr,
        )
        concurrent.futures.thread._threads_queues.clear()
        # https://stackoverflow.com/questions/49992329/the-workers-in-threadpoolexecutor-is-not-really-daemon
        for result, config in crawling_results:
            save_crawling_query(result, config)
        # TODO with attacks
        exit(1)
    except Exception as e:
        cprint(f"Error: {e}", color="red", file=sys.stderr)
