import json
import os
import re
import sys
from termcolor import cprint
import threading

google_dorking_results = []
crawling_results = []
xss_attack_results = []

LOCKS = {
    "dorking": threading.Lock(),
    "crawl": threading.Lock(),
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
        if os.path.exists(filename):
            with open(filename, "r+") as f:
                json.dump(vectors, f)
        else:
            with open(filename, "w"):
                json.dump(vectors, f)
        cprint("Written payloads to file", "green", file=sys.stderr)


def get_processed_dorks(settings):
    """
    Reads the experiment JSON file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings.get("dorking_json", "")):
        with open(settings["dorking_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                processed_dorks.add(row.get("dork", ""))

    return processed_dorks


def get_processed_crawled(settings):
    """
    TODO: Implement this function
    Reads the experiment JSON file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings.get("crawl_json", "")):
        with open(settings["crawl_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                processed_dorks.add(row.get("seedUrl", ""))

    return processed_dorks


def get_processed_crawled_form_dom(settings):
    """
    TODO: Implement this function
    Reads the experiment JSON file to get the list of processed dorks.
    """
    processed_dorks = set()
    if os.path.exists(settings.get("crawl_json", "")):
        with open(settings["crawl_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                processed_dorks.add(row.get("seedUrl", ""))

    return processed_dorks


def get_processed_xss(settings):
    """
    Reads the experiment JSON file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings.get("xss_json", "")):
        with open(settings["xss_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                processed_dorks.add((row.get("url", ""), row.get("payload", "")))

    return processed_dorks


def get_attacked_xss(settings):
    """
    Reads the experiment JSON file to get the list of processed dorks.
    """
    processed_dorks = set()

    if os.path.exists(settings.get("xss_json", "")):
        with open(settings["xss_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                processed_dorks.add((row.get("url", ""), row.get("payload", "")))

    return processed_dorks


def get_links(settings):
    links = set()
    if os.path.exists(settings.get("dorking_json", "")):
        with open(settings["dorking_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                if row.get("category", "") == "xss" and settings.get("do_xss", False):
                    links.add(row.get("url", ""))
                elif row.get("category", "") == "sqli" and settings.get(
                    "do_sqli", False
                ):
                    links.add(row.get("url", ""))
    return links


def get_xss_links(settings):
    """
    Reads the experiment JSON file to get the list of XSS-related links.
    """
    xss_links = set()

    if os.path.exists(settings.get("dorking_json", "")):
        with open(settings["dorking_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                if row.get("category", "") == "xss":
                    xss_links.add(row.get("url", ""))

    return xss_links


def get_last_processed_ids(settings):
    """
    Get the last processed dork_id, link_id, and attack_id from the JSON file.
    """
    last_dork_id = 0
    last_link_id = 0
    last_attack_id = 0

    if os.path.exists(settings.get("dorking_json", "")):
        with open(settings["dorking_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                last_dork_id = int(row.get("dork_id", 0))
                last_link_id = int(row.get("link_id", 0))
                last_attack_id = int(row.get("attack_id", 0))

    return last_dork_id, last_link_id, last_attack_id


def get_last_processed_crawl_ids(settings):
    """
    Get the last processed dork_id, link_id, and attack_id from the JSON file.
    """
    last_crawl_id = 0

    if os.path.exists(settings.get("crawl_json", "")):
        with open(settings["crawl_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                last_crawl_id = int(row.get("crawl_id", 0))
    return last_crawl_id


# Thread-safe addition to results lists
def save_dorking_query(result, settings):
    """
    Safely adds results to the single experiment JSON file with tracking IDs.
    """
    dork_id, category, urls, dork = result
    with LOCKS["dorking"]:
        if os.path.exists(settings.get("dorking_json", "")):
            with open(settings["dorking_json"], mode="r") as file:
                data = json.load(file)
        else:
            data = []

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
                    attack_id = last_attack_id  # Start attack_id from 1 for each link
                    # Success and payload fields are initially empty
                    row = {
                        "dork_id": dork_id,
                        "link_id": link_id,
                        "attack_id": attack_id,
                        "category": category,
                        "url": url,
                        "dork": dork,
                        "success": "yes",
                        "payload": "",
                    }
                    data.append(row)
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
                link_id += 1  # Increment link_id for next link
        else:
            # Add a row indicating no URLs found for this dork
            # No URLs found
            row = {
                "dork_id": dork_id,
                "link_id": link_id,
                "attack_id": last_attack_id,
                "category": category,
                "url": "",
                "dork": dork,
                "success": "no",
                "payload": "",
            }
            data.append(row)
            cprint(f"No URLs found for {category} dorks...", "red", file=sys.stderr)

        with open(settings["dorking_json"], mode="w") as file:
            json.dump(data, file)


def get_crawling_results(settings):
    """
    Reads the experiment JSON file to get the list of processed dorks.
    """
    crawling_results = []

    color_codes = [
        "\033[97m",  # white
        "\033[92m",  # green
        "\033[91m",  # red
        "\033[93m",  # yellow
        "\033[0m",  # end
        "\033[7;91m",  # back
        "\033[93m[!]\033[0m",  # info
        "\033[94m[?]\033[0m",  # que
        "\033[91m[-]\033[0m",  # bad
        "\033[92m[+]\033[0m",  # good
        "\033[97m[~]\033[0m",  # run
    ]

    if os.path.exists(settings.get("crawl_json", "")):
        with open(settings["crawl_json"], mode="r") as file:
            data = json.load(file)
            for row in data:
                cprint(
                    f"Getting {row} to experiment list...",
                    "blue",
                    file=sys.stderr,
                )
                # dom_parsed = re.sub(r"\\u001b\[93m|\\u001b\[0m", "", str(row.get("doms", "")))
                # dom_parsed = dom_parsed.replace("\\\\\\\\", "\\\\")

                dom_parsed = row.get("doms", "")

                for color in color_codes:
                    for dom in dom_parsed:
                        if isinstance(dom, str):
                            dom = dom.replace(color, "")

                cprint(
                    f"Getting {dom_parsed}  to experiment list under category crawl DOM",
                    "blue",
                    file=sys.stderr,
                )

                # dom_parsed = json.loads(dom_parsed)

                forms_parsed = row.get(
                    "forms", ""
                )  # str(row.get("forms", "")).strip("'<>() ").replace("'", '"')
                cprint(
                    f"Getting {forms_parsed} to experiment list under category crawl DOM",
                    "blue",
                    file=sys.stderr,
                )
                # forms_parsed = json.loads(forms_parsed)

                crawling_results.append(
                    (
                        row.get("seedUrl", ""),  # TODO
                        dom_parsed,
                        forms_parsed,
                    )
                )

    return crawling_results


def save_crawling_query(result, settings):
    """
    Safely adds results to the single experiment JSON file with tracking IDs.
    """
    seedUrl, forms_temps, domURLs_temps = result
    with LOCKS["crawl"]:
        with open(settings["crawl_json"], mode="r") as file:
            data = json.load(file)
            crawl_id = get_last_processed_crawl_ids(settings)

        with open(settings["crawl_json"], mode="w") as file:
            crawl_id += 1  # Increment link_id for next link
            if seedUrl:
                cprint(
                    f"Adding {len(seedUrl)} URLs to experiment list...",
                    "blue",
                    file=sys.stderr,
                )
                row = {
                    "crawl_id": crawl_id,
                    "seedUrl": seedUrl,
                    "success": "yes",
                    "doms": domURLs_temps,
                    "forms": forms_temps,
                }  # Success and payload columns are initially empty
                data.append(row)
                cprint(
                    f"Added {domURLs_temps} & {forms_temps} to experiment list under category crawl DOM",
                    "blue",
                    file=sys.stderr,
                )
            else:
                # Write a row indicating no URLs found for this dork
                row = {
                    "crawl_id": crawl_id,
                    "seedUrl": seedUrl,
                    "success": "no",
                    "doms": "no",
                    "forms": "no",
                }  # No URLs found
                data.append(row)
                cprint(
                    f"No URLs found for {seedUrl} crawling...", "red", file=sys.stderr
                )
            json.dump(data, file)


def update_xss_json(dork_id, link_id, attack_id, urls, dork, settings):
    """
    Update the XSS JSON file with the results.
    """
    with LOCKS["xss"]:
        with open(settings["xss_json"], mode="r+") as file:
            data = json.load(file)
        with open(settings["xss_json"], mode="w") as file:
            for url in urls:
                row = {
                    "dork_id": dork_id,
                    "link_id": link_id,
                    "attack_id": attack_id,
                    "url": url,
                    "dork": dork,
                    "success": "no",
                    "payload": "",
                    "github_success": "no",
                    "sqli_success": "no",
                    "xss_success": "no",
                }
                data.append(row)
            json.dump(data, file)


def update_sqli_json(dork_id, link_id, attack_id, urls, dork, settings):
    """
    Update the SQLi JSON file with the results.
    """
    with LOCKS["sqli"]:
        with open(settings["sqli_json"], mode="r+") as file:
            data = json.load(file)
        with open(settings["sqli_json"], mode="w") as file:
            for url in urls:
                row = {
                    "dork_id": dork_id,
                    "link_id": link_id,
                    "attack_id": attack_id,
                    "url": url,
                    "dork": dork,
                    "success": "no",
                    "payload": "",
                }
                data.append(row)
            json.dump(data, file)


def update_attack_result(
    settings, dork_id, link_id, attack_id, category, success, payload
):
    """
    Update the attack result in the JSON file.
    """
    rows = []
    if settings.get("do_dorking_github", False):
        csv_headers = [
            "dork_id",
            "link_id",
            "attack_id",
            "category",
            "url",
            "dork",
            "success",
            "payload",
            "github_success",
            "sqli_success",
            "xss_success",
        ]
    else:
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

    with LOCKS["dorking"]:
        with open(settings["dorking_json"], mode="r") as file:
            data = json.load(file)
        with open(settings["dorking_json"], mode="w") as file:
            for row in data:
                if (
                    int(row.get("dork_id", 0)) == dork_id
                    and int(row.get("link_id", 0)) == link_id
                    and int(row.get("attack_id", 0)) == attack_id
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

        with open(settings["dorking_json"], mode="r+") as file:
            json.dump(rows, file)

    # Update separate XSS and SQLi JSON files
    if category == "xss" and "xss_json" in settings:
        update_attack_specific_json(
            settings["xss_json"], dork_id, link_id, attack_id, success, payload
        )
    elif category == "sqli" and "sqli_json" in settings:
        update_attack_specific_json(
            settings["sqli_json"], dork_id, link_id, attack_id, success, payload
        )


def update_attack_specific_json(
    json_file_path, dork_id, link_id, attack_id, success, payload
):
    """
    Update the specific attack JSON file (XSS or SQLi).
    """
    rows = []
    with open(json_file_path, mode="r") as file:
        data = json.load(file)
    with open(json_file_path, mode="w") as file:
        for row in data:
            if (
                int(row.get("dork_id", 0)) == dork_id
                and int(row.get("link_id", 0)) == link_id
                and int(row.get("attack_id", 0)) == attack_id
            ):
                row["success"] = "yes" if success else "no"
                row["payload"] = payload
            rows.append(row)

    with open(json_file_path, mode="r+") as file:
        json.dump(rows, file)
