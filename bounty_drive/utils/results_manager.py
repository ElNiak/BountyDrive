import csv
import os
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


def get_processed_dorks(settings):
    """
    Reads the experiment CSV file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings["experiment_file_path"]):
        with open(settings["experiment_file_path"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                processed_dorks.add(row["dork"])

    return processed_dorks


def get_xss_links(settings):
    """
    Reads the experiment CSV file to get the list of XSS-related links.
    """
    xss_links = set()

    if os.path.exists(settings["experiment_file_path"]):
        with open(settings["experiment_file_path"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["category"] == "xss":
                    xss_links.add(row["url"])

    return xss_links


def get_last_processed_ids(settings):
    """
    Get the last processed dork_id, link_id, and attack_id from the CSV file.
    """
    last_dork_id = 0
    last_link_id = 0
    last_attack_id = 0

    if os.path.exists(settings["experiment_file_path"]):
        with open(settings["experiment_file_path"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                last_dork_id = int(row["dork_id"])
                last_link_id = int(row["link_id"])
                last_attack_id = int(row["attack_id"])

    return last_dork_id, last_link_id, last_attack_id


# Thread-safe addition to results lists
def safe_add_result(result, settings):
    """
    Safely adds results to the single experiment CSV file with tracking IDs.
    """
    dork_id, category, urls, dork = result
    with LOCKS["experiment"]:
        with open(settings["experiment_file_path"], mode="a", newline="") as file:
            writer = csv.writer(file)
            _, link_id, last_attack_id = get_last_processed_ids(settings)
            link_id += 1  # Increment link_id for next link
            if urls:
                cprint(
                    f"Adding {len(urls)} URLs to experiment list...",
                    "blue",
                    file=sys.stderr,
                )
                for url in urls:
                    if url and "https://www.google.com/sorry/" not in url:
                        attack_id = (
                            last_attack_id  # Start attack_id from 1 for each link
                        )
                        row = [
                            dork_id,
                            link_id,
                            attack_id,
                            category,
                            url,
                            dork,
                            "yes",
                            "",
                        ]  # Success and payload columns are initially empty
                        if settings["do_dorking_github"]:
                            row.append("no")
                        if settings["do_sqli"]:
                            row.append("no")
                        if settings["do_xss"]:
                            row.append("no")
                        writer.writerow(row)
                        cprint(
                            f"Added {url} to experiment list under category {category}",
                            "blue",
                            file=sys.stderr,
                        )
                        attack_id += 1  # Increment attack_id for next attack
                    else:
                        cprint(
                            f"Google blocked us from accessing {url}",
                            "red",
                            file=sys.stderr,
                        )
            else:
                # Write a row indicating no URLs found for this dork
                row = [
                    dork_id,
                    link_id,
                    last_attack_id,
                    category,
                    "",
                    dork,
                    "no",
                    "",
                ]  # No URLs found
                if settings["do_dorking_github"]:
                    row.append("no")
                if settings["do_sqli"]:
                    row.append("no")
                if settings["do_xss"]:
                    row.append("no")
                writer.writerow(row)
                cprint(f"No URLs found for {category} dorks...", "red", file=sys.stderr)


def update_attack_result(
    settings, dork_id, link_id, attack_id, category, success, payload
):
    """
    Update the attack result in the CSV file.
    """
    rows = []
    with LOCKS["experiment"]:
        with open(settings["experiment_file_path"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if (
                    int(row["dork_id"]) == dork_id
                    and int(row["link_id"]) == link_id
                    and int(row["attack_id"]) == attack_id
                ):
                    row["success"] = "yes" if success else "no"
                    row["payload"] = payload
                    if category == "github" and "github_success" in row:
                        row["github_success"] = "yes" if success else "no"
                    if category == "sqli" and "sqli_success" in row:
                        row["sqli_success"] = "yes" if success else "no"
                    if category == "xss" and "xss_success" in row:
                        row["xss_success"] = "yes" if success else "no"
                rows.append(row)

        with open(settings["experiment_file_path"], mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(rows)
