#########################################################################################
# Proxy related functions
#########################################################################################

# Round-robin proxy generator
import itertools
import random
import threading
import time

import requests
from termcolor import cprint
import concurrent.futures
from tqdm import tqdm
from typing import List, Literal
import sys

from utils.app_config import PROXY_MEAN_DELAY, USER_AGENTS

# TODO use nordvpn gateway proxy list

# https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&proxy_format=protocolipport&format=text&timeout=20000
def update_proxy_list():
    pass


def round_robin_proxies(proxies):
    return itertools.cycle(proxies)


# Function to check if a proxy is up
def is_proxy_alive(proxy, retry=0):
    try:
        cprint(
            f"Testing proxy {proxy}, retry n° {retry} ...",
            "yellow",
            file=sys.stderr,
        )
        response = requests.get(
            "http://www.google.com/search?q=test",
            proxies={"http": proxy, "https": proxy},
            timeout=PROXY_MEAN_DELAY,
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
            return is_proxy_alive(proxy=proxy, retry=retry + 1)
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


def setup_proxies():
    proxies = load_proxies()
    proxies_cp = proxies.copy()
    dead_proxies = 0
    total_proxies = len(proxies)

    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_search = {
            executor.submit(is_proxy_alive, proxy): proxy for proxy in proxies_cp
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
        cprint(f"Up proxies: {len(proxies)}")

    return proxies


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
