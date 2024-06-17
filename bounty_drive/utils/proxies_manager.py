#########################################################################################
# Proxy related functions
#########################################################################################

# Round-robin proxy generator
import csv
import itertools
import json
import os
import random
import threading
import time

import requests
from termcolor import cprint
import concurrent.futures
from tqdm import tqdm
from typing import List, Literal
import sys

from utils.app_config import USER_AGENTS
from fp.fp import FreeProxy, FreeProxyException


def round_robin_proxies(proxies):
    return itertools.cycle(proxies)


# Function to check if a proxy is up
def is_proxy_alive(proxy, config, retry=0):
    try:
        cprint(
            f"Testing proxy {proxy}, retry n° {retry} ...",
            "yellow",
            file=sys.stderr,
        )
        # TODO use request_manager
        response = requests.get(
            "http://www.google.com/search?q=test",
            proxies={"http": proxy, "https": proxy},
            timeout=config["proxy_mean_delay"],
            headers={"User-Agent": random.choice(USER_AGENTS)},
            verify=False,
        )
        if response and response.status_code == 429 and retry < 3:
            retry_after = int(response.headers.get("Retry-After", 60))
            cprint(
                f"Proxy {proxy}: Retry after {retry_after} secs ...",
                "red",
                file=sys.stderr,
            )
            time.sleep(retry_after)
            return is_proxy_alive(proxy=proxy, retry=retry + 1, config=config)
        return response.status_code == 200, proxy
    except requests.exceptions.RequestException as e:
        cprint(
            f"Proxy {proxy} error with : {e}",
            "red",
            file=sys.stderr,
        )
        return False, proxy


# Load proxies from file
def load_proxies(file="proxies/free-proxy-list.txt"):
    with open(file, "r") as file:
        return [line.strip() for line in file if line.strip()]


def prepare_proxies(proxy, config):
    if proxy and "username:password" in proxy:
        nord_vpn_user_pass = random.choice(config["nord_vpn_login"])
        proxy = proxy.replace("username", nord_vpn_user_pass[0]).replace(
            "password", nord_vpn_user_pass[1]
        )
        proxies = {"https": proxy}

    else:
        proxies = {"http": proxy, "https": proxy}
    return proxies


def setup_proxies(config):
    proxies = []
    if config["use_free_proxy_file"]:
        cprint("Loading proxies from file ...", "yellow", file=sys.stderr)
        proxies = load_proxies()
        proxies_cp = proxies.copy()
        dead_proxies = 0
        total_proxies = len(proxies)

        lock = threading.Lock()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_search = {
                executor.submit(is_proxy_alive, proxy, config, 0): proxy
                for proxy in proxies_cp
            }
            for future in tqdm(
                concurrent.futures.as_completed(future_to_search),
                total=len(future_to_search),
                desc="Checking proxies",
                unit="proxy",
                leave=True,
                position=0,
            ):
                result = future.result()
                if result:
                    with lock:
                        if not result[0]:
                            dead_proxies += 1
                            cprint(
                                f"Removing dead proxy {result[1]}, dead proxies {dead_proxies}/{total_proxies}",
                                "red",
                                file=sys.stderr,
                            )
                            proxies.remove(result[1])
            cprint(f"Up free proxies: {len(proxies)}")

    if config["use_free_proxy"]:
        cprint("Using Free proxies ", "yellow", file=sys.stderr)
        try:
            free_proxy = FreeProxy(
                google=None, rand=True, https=True, timeout=10
            ).get_proxy_list(repeat=False)
            proxies += free_proxy
        except FreeProxyException as e:
            cprint(f"FreeProxyException: {e}", "red", file=sys.stderr)

    if config["use_nordvpn_proxy"]:
        config["nord_vpn_login"] = json.loads(config["nord_vpn_login"])
        cprint("Using NordVPN proxies ", "yellow", file=sys.stderr)
        if os.path.exists("proxies/nordvpn_login.csv"):
            with open("proxies/nordvpn_login.csv", "r") as file:
                nordvpn = list(csv.reader(file))
                for i in range(1, len(nordvpn)):
                    config["nord_vpn_login"].append([nordvpn[i][0], nordvpn[i][1]])
                cprint(
                    f"You have NordVPN account using these proxies {config['nord_vpn_login']}",
                    "green",
                    file=sys.stderr,
                )
            # https://stackoverflow.com/questions/64516109/how-to-use-nordvpn-servers-as-proxy-for-python-requests
            # TODO: curl -s https://nordvpn.com/api/server | jq -r ".[] | select(.features.socks==true) | [.domain, .name] | @tsv"
            with open("proxies/nordvpn-proxy-list.txt", "r") as file:
                for line in file.readlines():
                    line = line.replace("\n", "")
                    cprint(f"NordVPN Proxy: {line}", "yellow", file=sys.stderr)
                    p = (
                        "socks5h://"  # socks5h enable hostname resolution
                        + "username"
                        + ":"
                        + "password"
                        + "@"
                        + line
                        + ":1080"
                    )
                    proxies += [p]
        else:
            cprint(
                "You need to provide your NordVPN login details in proxies/nordvpn_login.csv",
                "red",
                file=sys.stderr,
            )
    config["proxies"] = list(set(proxies))
    cprint(f"Proxy: {config['proxies']}", "green", file=sys.stderr)


# TODO: https://stackoverflow.com/questions/55872164/how-to-rotate-proxies-on-a-python-requests
class Proxy:
    """container for a proxy"""

    def __init__(self, ip, type_="datacenter") -> None:
        self.ip: str = ip
        self.type: Literal["datacenter", "residential"] = type_
        _, _, self.subnet, self.host = ip.split(":")[0].split(".")
        self.status: Literal["alive", "unchecked", "dead"] = "unchecked"
        self.last_used: int = None

    def __repr__(self) -> str:
        return self.ip

    def __str__(self) -> str:
        return self.ip


class Rotator:
    """weighted random proxy rotator"""

    def __init__(self, proxies: List[Proxy]):
        self.proxies = proxies
        self._last_subnet = None

    def weigh_proxy(self, proxy: Proxy):
        weight = 1_000
        if proxy.subnet == self._last_subnet:
            weight -= 500
        if proxy.status == "dead":
            weight -= 500
        if proxy.status == "unchecked":
            weight += 250
        if proxy.type == "residential":
            weight += 250
        if proxy.last_used:
            _seconds_since_last_use = time.time() - proxy.last_used
            weight += _seconds_since_last_use
        return weight

    def get(self):
        proxy_weights = [self.weigh_proxy(p) for p in self.proxies]
        proxy = random.choices(
            self.proxies,
            weights=proxy_weights,
            k=1,
        )[0]
        proxy.last_used = time.time()
        self.last_subnet = proxy.subnet
        return proxy
