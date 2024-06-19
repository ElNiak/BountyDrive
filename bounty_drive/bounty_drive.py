# /usr/bin/python3
import sys

# TO get stacktrace in case of segfault
# gdb pypy3; run bounty_drive.py
# import faulthandler
# faulthandler.enable(file=sys.stderr, all_threads=True)

import utils.logger
from utils.logger import *


from termcolor import cprint
import os
import csv
import concurrent.futures

from tqdm import tqdm

from attacks.dorks.google_dorking import (
    google_search_with_proxy,
    load_google_dorks_and_search,
)

from attacks.dorks.github_dorking import *

from reporting.results_manager import (
    get_last_processed_ids,
    get_processed_dorks,
    get_xss_links,
)
from vpn_proxies.proxies_manager import round_robin_proxies, setup_proxies
from vpn_proxies.vpn_manager import setup_vpn

from attacks.xss.xss import test_vulnerability_xss
from attacks.xss.xss_config import *

from attacks.sqli.sqli_scan_config import *
from attacks.sqli.sqli import test_vulnerability_sqli

from utils.banner import *
from utils.banner import load_animation


import configparser

os.system("clear")

#########################################################################################
# Main function
#########################################################################################


def read_config(file_path):
    """
    Reads the configuration file and returns the settings as a dictionary.
    """
    config = configparser.ConfigParser()
    config.read(file_path)

    settings = {
        # Settings
        "extension": config["Settings"].get("extension"),
        "subdomain": config["Settings"].getboolean("subdomain"),
        "do_web_scrap": config["Settings"].getboolean("do_web_scrap"),
        "target_file": config["Settings"].get("target_file"),
        "experiment_file_path": config["Settings"].get("experiment_file_path"),
        "max_thread": config["Settings"].getint("max_thread", 30),
        "logging": config["Settings"].get("logging", "DEBUG"),
        # Google Dorking
        "do_dorking_google": config["GoogleDorking"].getboolean("do_dorking_google"),
        "total_output": config["GoogleDorking"].getint("total_output"),
        "page_no": config["GoogleDorking"].getint("page_no"),
        "default_total_output": config["GoogleDorking"].getint("default_total_output"),
        "default_page_no": config["GoogleDorking"].getint("default_page_no"),
        "lang": config["GoogleDorking"].get("lang"),
        "use_selenium": config["GoogleDorking"].getboolean("use_selenium"),
        # Github Dorking
        "do_dorking_github": config["GithubDorking"].getboolean("do_dorking_github"),
        # XSS
        "do_xss": config["XSS"].getboolean("do_xss"),
        "encode_xss": config["XSS"].getboolean("encode_xss"),
        "fuzz_xss": config["XSS"].getboolean("fuzz_xss"),
        "blind_xss": config["XSS"].getboolean("blind_xss"),
        "do_sqli": config["SQLi"].getboolean("do_sqli"),
        # Crawling
        "do_crawl": config["crawler"].getboolean("do_crawl", True),
        "skip_dom": config["crawler"].getboolean("skip_dom", False),
        "level": config["crawler"].getint("level", 1),
        # Proxy
        "use_proxy": config["Proxy"].getboolean("use_proxy"),
        "use_free_proxy_file": config["Proxy"].getboolean("use_free_proxy_file"),
        "use_free_proxy": config["Proxy"].getboolean("use_free_proxy"),
        "use_nordvpn_proxy": config["Proxy"].getboolean("use_nordvpn_proxy"),
        "proxies": config["Proxy"].get("proxies"),
        "proxy_mean_delay": config["Proxy"].getint("proxy_mean_delay"),
        "proxy_factor": config["Proxy"].getint("proxy_factor"),
        # VPN
        "use_vpn": config["VPN"].getboolean("use_vpn"),
        "use_nordvpn": config["VPN"].getboolean("use_nordvpn"),
        "nord_vpn_login": config["VPN"].get("nord_vpn_login"),
        # Search
        "default_extension": config["Search"].get("default_extension"),
        "search_extension": config["Search"].get("extension"),
        "recursive": config["Search"].getboolean("recursive"),
        # Delay
        "initial_delay": config["Delay"].getint("initial_delay"),
        "delay_factor": config["Delay"].getint("delay_factor"),
        "long_delay": config["Delay"].getint("long_delay"),
        "max_delay": config["Delay"].getint("max_delay"),
        "request_delay": config["Delay"].getint("request_delay"),
        "waf_delay": config["Delay"].getint("waf_delay"),
        # Rate
        "rate_per_minute": config["Rate"].getint("rate_per_minute"),
        "current_delay": config["Rate"].getint("current_delay"),
    }

    return settings


def get_user_input(config_file="configs/config.ini"):
    """
    Collect user input from configuration file.
    """
    config = read_config(config_file)

    categories = []

    # Define headers based on enabled parameters
    setup_csv(config, categories)

    cprint(
        f"-Extension: {config['extension']}\n-Total Output: {config['total_output']}\n-Page No: {config['page_no']}\n-Do Google Dorking: {config['do_dorking_google']}\n-Do Github Dorking {config['do_dorking_github']}\n-Do XSS: {config['do_xss']}\n-Do SQLi: {config['do_sqli']},\n Domain: {config['subdomain']}\n-Use Proxy: {config['use_proxy']}",
        "green",
        file=sys.stderr,
    )

    if config["use_proxy"]:
        setup_proxies(config)

    if config["use_vpn"]:
        setup_vpn(config)

    last_dork_id, last_link_id, last_attack_id = get_last_processed_ids(config)

    if config["subdomain"]:
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

        saved_total_output = config["total_output"]
        current_total_output = 10
        config["total_output"] = current_total_output
        search_tasks_with_proxy = []

        number_of_worker = min(len(proxies), 30)
        cprint(f"Number of workers: {number_of_worker}", "yellow", file=sys.stderr)

        with open(config["target_file"], "r") as file:
            subdomain_list = file.read().splitlines()
            if len(subdomain_list) >= last_dork_id:
                for domain in subdomain_list:
                    processed = False
                    for category in categories:
                        with open(
                            config["experiment_file_path"], mode="r", newline=""
                        ) as file:
                            reader = csv.DictReader(file)
                            for row in reader:
                                if domain in row["dork"]:
                                    processed = True

                        if not processed:
                            proxy = next(proxy_cycle)
                            search_tasks_with_proxy.append(
                                {
                                    "dork": "",
                                    "proxy": proxy,
                                    "category": category,
                                    "domain": domain,
                                }
                            )
                            cprint(
                                f"Initial Dorking search for based targets {domain} - {category}",
                                "yellow",
                                file=sys.stderr,
                            )
                        else:
                            cprint(
                                f"Already initialized Dorking search for based targets {domain} - {category}",
                                "yellow",
                                file=sys.stderr,
                            )

            processed_dorks = get_processed_dorks(config)
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
                        processed_dorks,
                    ): task
                    for task in search_tasks_with_proxy
                }
                for future in tqdm(
                    concurrent.futures.as_completed(future_to_search),
                    total=len(future_to_search),
                    desc="Initializing Dorking of targets",
                    unit="site",
                ):
                    task = future_to_search[future]
                    # try:
                    last_dork_id = future.result()

            config["subdomain"] = subdomain_list
    else:
        config["subdomain"] = [None]

    config["total_output"] = saved_total_output

    return config, last_dork_id, last_link_id, last_attack_id, categories


def setup_csv(config, categories):
    csv_headers = [
        "dork_id",
        "link_id",
        "attack_id",
        "category",
        "url",
        "dork",
        "success",
        "payload",
    ]
    if config["do_dorking_github"]:
        csv_headers.append("github_success")
    if config["do_sqli"]:
        sqli_csv_headers = [
            "dork_id",
            "link_id",
            "attack_id",
            "url",
            "dork",
            "success",
            "payload",
        ]
        sqli_csv = config["experiment_file_path"].replace(".csv", "_sqli.csv")
        config["sqli_csv"] = sqli_csv
        if not os.path.exists(sqli_csv) or os.path.getsize(sqli_csv) == 0:
            with open(sqli_csv, mode="a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(sqli_csv_headers)

        csv_headers.append("sqli_success")
        categories.append("sqli")
    if config["do_xss"]:
        xss_csv_headers = [
            "dork_id",
            "link_id",
            "attack_id",
            "url",
            "dork",
            "success",
            "payload",
            "is_dom",
            "is_form",
            "is_unknown",
            "already_attacked",
        ]
        xss_csv = config["experiment_file_path"].replace(".csv", "_xss.csv")
        config["xss_csv"] = xss_csv
        if not os.path.exists(xss_csv) or os.path.getsize(xss_csv) == 0:
            with open(xss_csv, mode="a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(xss_csv_headers)

        csv_headers.append("xss_success")
        categories.append("xss")

    if (
        not os.path.exists(config["experiment_file_path"])
        or os.path.getsize(config["experiment_file_path"]) == 0
    ):
        with open(config["experiment_file_path"], mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(csv_headers)


if __name__ == "__main__":
    try:
        load_animation()

        if len(sys.argv) == 2:
            (
                config,
                last_dork_id,
                last_link_id,
                last_attack_id,
                categories,
            ) = get_user_input(sys.argv[1])
        elif len(sys.argv) == 1:
            (
                config,
                last_dork_id,
                last_link_id,
                last_attack_id,
                categories,
            ) = get_user_input()
        else:
            cprint(
                "Invalid number of arguments (./py [config_file_path])",
                "red",
                file=sys.stderr,
            )
            exit()

        if config["do_dorking_google"]:
            cprint(
                "\nStarting Google dorking scan phase...\n", "yellow", file=sys.stderr
            )
            load_google_dorks_and_search(config, categories)

        if config["do_dorking_github"]:
            cprint(
                "\nStarting Github dorking scan phase...\n", "yellow", file=sys.stderr
            )
            raise NotImplementedError("Github dorking scan phase not implemented yet")
            load_github_dorks_and_search(config, categories)

        if config["do_sqli"]:
            raise NotImplementedError("SQLi phase not implemented yet")
            website_to_test = POTENTIAL_PATHS["sqli"][1]
            cprint(
                "\nTesting websites for SQL injection vulnerability...\n",
                "yellow",
                file=sys.stderr,
            )
            if not website_to_test:
                cprint(
                    "No websites found matching the dorks. Please adjust your search criteria.",
                    "red",
                    file=sys.stderr,
                )
            test_vulnerability_sqli(config)

        if config["do_xss"]:
            website_to_test = get_xss_links(config)
            cprint(
                "\nTesting websites for XSS vulnerability...\n",
                "yellow",
                file=sys.stderr,
            )
            if not website_to_test:
                cprint(
                    "No websites found matching the dorks. Please adjust your search criteria.",
                    "red",
                    file=sys.stderr,
                )
            test_vulnerability_xss(config, website_to_test)

        cprint(banner_terminal_res, "green", file=sys.stderr)

        # if do_sqli and VULN_PATHS["sqli"][1]:
        #     raise NotImplementedError("SQLi phase not implemented yet")
        #     cprint(
        #         "The following targets are affected with SQLi:", "red", file=sys.stderr
        #     )
        #     for target in VULN_PATHS["sqli"][1]:
        #         cprint(target, "red", file=sys.stderr)

        # if do_xss and VULN_PATHS["xss"][1]:
        #     cprint(
        #         "The following targets are affected with XSS:", "red", file=sys.stderr
        #     )
        #     for target in VULN_PATHS["xss"][1]:
        #         cprint(target, "red", file=sys.stderr)
    # except Exception as e:
    #     cprint(f"Error: {e}", "red", file=sys.stderr)
    finally:
        sys.stderr = orig_stdout
        f.close()
