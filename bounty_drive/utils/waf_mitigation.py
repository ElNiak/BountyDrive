#########################################################################################
# WAF
#########################################################################################

# from https://github.com/s0md3v/XSStrike/blob/master/core/wafDetector.py
import glob
import json
import re
import eventlet, requests
from termcolor import cprint

from utils.request_manager import start_request

# from bounty_drive.attacks.xss.xss_config import XSS_TEST_PAYLOAD


def waf_detector(proxies, url, params, headers, GET, mode="xss"):
    # a payload which is noisy enough to provoke the WAF
    if mode == "xss":
        noise = XSS_TEST_PAYLOAD
    else:
        noise = "../../../etc/passwd"
    params["xss"] = noise
    # Opens the noise injected payload
    response = start_request(
        proxies=proxies, url=url, params=params, headers=headers, GET=GET
    )
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    cprint("Waf Detector code: {}".format(code))
    cprint("Waf Detector headers:", response.headers)

    waf_signatures_files = glob.glob("waf_signature/*.json", recursive=True)
    bestMatch = [0, None]
    for waf_signatures_file in waf_signatures_files:
        with open(waf_signatures_file, "r") as file:
            wafSignatures = json.load(file)
        if int(code) >= 400:
            for wafName, wafSignature in wafSignatures.items():
                score = 0
                pageSign = wafSignature["page"]
                codeSign = wafSignature["code"]
                headersSign = wafSignature["headers"]
                if pageSign:
                    if re.search(pageSign, page, re.I):
                        score += 1
                if codeSign:
                    if re.search(codeSign, code, re.I):
                        score += 0.5  # increase the overall score by a smaller amount because http codes aren't strong indicators
                if headersSign:
                    if re.search(headersSign, headers, re.I):
                        score += 1
                # if the overall score of the waf is higher than the previous one
                if score > bestMatch[0]:
                    del bestMatch[:]  # delete the previous one
                    bestMatch.extend([score, wafName])  # and add this one
        else:
            return None
    if int(code) >= 400:
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None


def heuristic_scanner(
    url,
    payload,
    method,
    cookie,
    headers,
    timeout,
    ssl,
    data,
    verbose,
    silent,
    stable,
    delay,
):
    """
    A basic scan to check if the URL is vulnerable or not
    """
    url = url.strip()
    scheme, host = urlparse(url).scheme, urlparse(url).netloc
    url = scheme + "://" + host
    if not url.endswith("/"):
        url = url + "/"
    final_url = url + payload
    response = requester.do(
        final_url,
        method,
        cookie,
        headers,
        timeout,
        ssl,
        data,
        verbose,
        silent,
        stable,
        delay,
    )
    try:
        code, rheaders = response[1], str(response[2])
        if not int(code) >= 400:
            if "nefcore" and "crlfsuite" in rheaders:
                heuristic_result.add(final_url)
    except TypeError:
        pass


# https://github.com/MichaelStott/CRLF-Injection-Scanner/blob/master/scanner.py#L28
class CrlfScanner:
    """Scans URLs for CRLF injection."""

    # List of web protocols.
    PROTOCOL_LIST = ["http", "https"]

    # Append this to beginning of escape sequence.
    APPEND_LIST = ["", "crlf", "?crlf=", "#"]

    # List of escape sequences that possibly result in crlf.
    ESCAPE_LIST = ["%0d", "%0a", "%0d%0a", "%23%0d", "%23%0a", "%23%0d%0a"]

    # By default, the scanner will try to inject a Set-Cookie statment.
    DEFAULT_INJ = "Set-Cookie:param=crlf;"

    # If we don't get a response within the TIMEOUT, terminate the current scan.
    TIMEOUT = 5

    def __init__(self):
        self.inj_str = self.DEFAULT_INJ

    def generate_vuln_urls(self, url):
        """Generate URLS that may be vulnerable to CRLF injection."""
        vuln_urls = []
        if not url.endswith("/"):
            url += "/"
        for protocol in self.PROTOCOL_LIST:
            for append in self.APPEND_LIST:
                for escape in self.ESCAPE_LIST:
                    vuln_urls.append(
                        protocol + "://" + url + append + escape + self.inj_str
                    )
        return vuln_urls

    def scan(self, url):
        """Scan target URL for CRLF injection"""
        result = False
        session = requests.Session()
        with eventlet.Timeout(self.TIMEOUT):
            try:
                session.get(url)
            except KeyboardInterrupt:
                raise
            except:
                pass
            if (
                "param" in session.cookies.get_dict()
                and "crlf" in session.cookies.get_dict().values()
            ):
                result = True
        return result
