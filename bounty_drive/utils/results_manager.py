import sys
import threading

from termcolor import cprint
from utils.app_config import *
             
#########################################################################################
# File writing functions
#########################################################################################

# Define file paths
# Initialize locks for thread-safe file writing
# TODO make more modular

LOCKS = {
    "sqli": threading.Lock(),
    "xss": threading.Lock(),
    "api": threading.Lock(),
    "web": threading.Lock(),
    "secret": threading.Lock(),
    "dlphp": threading.Lock(),
    "backup": threading.Lock(),
    "github": threading.Lock(),
}

# Thread-safe addition to results lists
def safe_add_result(result):
    # TODO category not working, all go to xss
    category, urls = result
    if urls:
        cprint(f"Adding {len(urls)} URLs to {category} list...", 'blue', file=sys.stderr)
        for url in urls:
            if url:
                if "https://www.google.com/sorry/" not in url:
                    if "github.com" in url:
                        with LOCKS["github"]:
                            with open(GITHUB_FILE_PATH, "a") as file:
                                file.write(url + "\n")
                            POTENTIAL_PATHS["github"][1].add(url)
                            cprint(f"Added {url} to github list", 'green', file=sys.stderr)
                    else:
                        with LOCKS[category]:  # Ensure thread-safe write operation
                            with open(POTENTIAL_PATHS[category][0], "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            POTENTIAL_PATHS[category][1].add(url)  # Optionally maintain the set
                            cprint(f"Added {url} to {category} list", 'green', file=sys.stderr)
                else:
                    cprint(f"Google blocked us from accessing {url}", 'red', file=sys.stderr)
    else:
        cprint(f"No URLs found for {category} dorks...", 'red', file=sys.stderr)
