#########################################################################################
# WAF
#########################################################################################

# from https://github.com/s0md3v/XSStrike/blob/master/core/wafDetector.py
import json
import re
import sys

from termcolor import cprint

from utils.request_manager import start_request


def waf_detector(proxies, url, params, headers, GET, delay, timeout):
    with open(sys.path[0] + "waf_signatures.json", "r") as file:
        wafSignatures = json.load(file)
    # a payload which is noisy enough to provoke the WAF
    noise = '<script>alert("XSS")</script>'
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

    if int(code) >= 400:
        bestMatch = [0, None]
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
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None
