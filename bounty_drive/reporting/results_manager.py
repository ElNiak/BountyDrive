import csv
import os
import sys

from termcolor import cprint

import threading

google_dorking_results = []
xss_attack_results = []

LOCKS = {
    "experiment": threading.Lock(),
    "sqli": threading.Lock(),
    "xss": threading.Lock(),
}
#########################################################################################
# File writing functions
#########################################################################################

# Define file paths
# Initialize locks for thread-safe file writing
# TODO make more modular


def write_xss_vectors(vectors, filename):
    with LOCKS["xss"]:
        with open(filename, "w") as f:
            for vs in vectors.values():
                for v in vs:
                    f.write("{}\n".format(v))
        cprint("Written payloads to file", "green", file=sys.stderr)


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


def get_processed_xss_crawled(settings):
    """
    TODO: Implement this function
    Reads the experiment CSV file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings["xss_csv"]):
        with open(settings["xss_csv"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                processed_dorks.add(row["seedUrl"])

    return processed_dorks


def get_processed_xss(settings):
    """
    Reads the experiment CSV file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings["xss_csv"]):
        with open(settings["xss_csv"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                processed_dorks.add((row["url"], row["payload"]))

    return processed_dorks


def get_attacked_xss(settings):
    """
    Reads the experiment CSV file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings["xss_csv"]):
        with open(settings["xss_csv"], mode="r", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                processed_dorks.add((row["url"], row["payload"]))

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
def save_dorking_query(result, settings):
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
                        if settings["do_dorking_github"] and category == "github":
                            row.append("no")
                        if settings["do_sqli"] and category == "sqli":
                            row.append("no")
                        if settings["do_xss"] and category == "xss":
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

    if settings["do_xss"] and category == "xss":
        update_xss_csv(dork_id, link_id, last_attack_id, urls, dork, settings)
    if settings["do_sqli"] and category == "sqli":
        update_sqli_csv(dork_id, link_id, last_attack_id, urls, dork, settings)


def update_xss_csv(dork_id, link_id, attack_id, urls, dork, settings):
    """
    Update the XSS CSV file with the results.
    """
    with LOCKS["xss"]:
        with open(settings["xss_csv"], mode="a", newline="") as file:
            writer = csv.writer(file)
            for url in urls:
                row = [
                    dork_id,
                    link_id,
                    attack_id,
                    url,
                    dork,
                    "no",
                    "",
                    "no",
                    "no",
                    "no",
                    "no",
                ]
                writer.writerow(row)


def update_sqli_csv(dork_id, link_id, attack_id, urls, dork, settings):
    """
    Update the SQLi CSV file with the results.
    """
    with LOCKS["sqli"]:
        with open(settings["sqli_csv"], mode="a", newline="") as file:
            writer = csv.writer(file)
            for url in urls:
                row = [dork_id, link_id, attack_id, url, dork, "no", ""]
                writer.writerow(row)


def update_attack_result(
    settings, dork_id, link_id, attack_id, category, success, payload
):
    """
    Update the attack result in the CSV file.
    """
    rows = []
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
    if settings["do_dorking_github"]:
        csv_headers.append("github_success")
    if settings["do_sqli"]:
        csv_headers.append("sqli_success")
    if settings["do_xss"]:
        csv_headers.append("xss_success")

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

    # Update separate XSS and SQLi CSV files
    if category == "xss" and "xss_csv" in settings:
        update_attack_specific_csv(
            settings["xss_csv"], dork_id, link_id, attack_id, success, payload
        )
    elif category == "sqli" and "sqli_csv" in settings:
        update_attack_specific_csv(
            settings["sqli_csv"], dork_id, link_id, attack_id, success, payload
        )


def update_attack_specific_csv(
    csv_file_path, dork_id, link_id, attack_id, success, payload
):
    """
    Update the specific attack CSV file (XSS or SQLi).
    """
    rows = []
    with open(csv_file_path, mode="r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if (
                int(row["dork_id"]) == dork_id
                and int(row["link_id"]) == link_id
                and int(row["attack_id"]) == attack_id
            ):
                row["success"] = "yes" if success else "no"
                row["payload"] = payload
            rows.append(row)

    with open(csv_file_path, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=reader.fieldnames)
        writer.writeheader()
        writer.writerows(rows)
