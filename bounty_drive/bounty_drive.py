#/usr/bin/python3
import sys
from termcolor import colored, cprint
import terminal_banner
import random
import os
import requests
import glob
import time
import threading
import concurrent.futures
import itertools
from tqdm import tqdm
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
import urllib.parse as urlparse
import subprocess
import logging
import re
import json

    
from bounty_drive.attacks.dorks.google_dorking import load_google_dorks_and_search
from bounty_drive.attacks.sqli.sqli import test_vulnerability_sqli
from bounty_drive.attacks.xss.xss import test_vulnerability_xss
from bounty_drive.utils.banner import load_animation
from bounty_drive.utils.proxies import setup_proxies
from attacks.dorks.github_dorking import *
from utils.app_config import *
from attacks.xss.xss_config import *
from attacks.sqli.sqli_scan_config import *
from utils.banner import *
from utils.logger import *
import utils.logger

os. system('clear')
  
#########################################################################################
# Main function
#########################################################################################          

def get_user_input():
    """
    Collect user input for website extension, total output, and starting page number, with default values.
    """
    extension    = input(colored(f"Please specify the website extension(eg- .in,.com,.pk) [default: {DEFAULT_EXTENSION}] -----> ", 'cyan')) or DEFAULT_EXTENSION
    subdomain    = input(colored(f"Do you want to restrict search to subdomain present in target.txt ? [default: true (vs false)] -----> ", 'cyan')) or "true"
    total_output = input(colored(f"Please specify the total no. of websites you want [default: {DEFAULT_TOTAL_OUTPUT}] ----> ", 'cyan')) or DEFAULT_TOTAL_OUTPUT
    page_no      = input(colored(f"From which Google page you want to start(eg- 1,2,3) [default: {DEFAULT_PAGE_NO}] ----> ", 'cyan')) or DEFAULT_PAGE_NO
    
    do_dorking_google   = input(colored(f"Do you want to do the Google dorking scan phase ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_dorking_github   = input(colored(f"Do you want to do the Github dorking scan phase ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    do_xss           = input(colored(f"Do you want to test for XSS vulnerability ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_encode_xss    = input(colored(f"Do you want to encode XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_fuzzing_xss   = input(colored(f"Do you want to fuzz XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_blind_xss     = input(colored(f"Do you want to test blind XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    do_sqli         = input(colored(f"Do you want to test for SQLi vulnerability ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    
    # Ensure numeric inputs are correctly converted to integers
    TOTAL_OUTPUT = int(total_output)
    PAGE_NO      = int(page_no)
    do_dorking_google   = True if do_dorking_google.lower() == "true" else False
    do_dorking_github   = True if do_dorking_github.lower() == "true" else False
    subdomain           = True if subdomain.lower() == "true" else False
    
    do_xss              = True if do_xss.lower() == "true" else False 
    ENCODE_XSS       = True if do_encode_xss.lower() == "true" else False
    FUZZ_XSS         = True if do_fuzzing_xss.lower() == "true" else False
    BLIND_XSS        = True if do_blind_xss.lower() == "true" else False
    
    do_sqli             = True if do_sqli.lower() == "true" else False
    if subdomain:
        # TODO allow multiple subdomains
        with open("target.txt", "r") as file:
            subdomain = file.read().splitlines()
        SUBDOMAIN = subdomain
    
    cprint(f"Extension: {extension}, Total Output: {total_output}, Page No: {page_no}, Do Google Dorking: {do_dorking_google}, Do Github Dorking {do_dorking_github}", 'green', file=sys.stderr)
    
    return extension, do_dorking_google, do_dorking_github, do_sqli, do_xss

if __name__ == "__main__":
    try:
        load_animation()
        if len(sys.argv) > 3:
            extension    = sys.argv[1]
            subdomain    = sys.argv[2]
            total_output = int(sys.argv[3])
            page_no      = int(sys.argv[4])
            do_dorking_google   = bool(sys.argv[5])
            do_dorking_github   = bool(sys.argv[6])
        else:
            extension, do_dorking_google, do_dorking_github, do_sqli, do_xss = get_user_input()
            
        proxies = setup_proxies()
        
        if do_dorking_google:
            cprint("\nStarting Google dorking scan phase...\n", 'yellow', file=sys.stderr)
            proxies, website_list_sqli,  website_list_xss, _, _, _, _, _ = load_google_dorks_and_search(extension, total_output, page_no, proxies)
            
        if do_dorking_github:
            cprint("\nStarting Github dorking scan phase...\n", 'yellow', file=sys.stderr)
            raise NotImplementedError("Github dorking scan phase not implemented yet")
            # proxies, _, _, _, _, _, _, _, website_list_git = load_github_dorks_and_search(extension, total_output, page_no, proxies)  
        
        def read_potential_sites():
            for key, value in POTENTIAL_PATHS.items():
                with open(value[0], 'r') as file:
                    POTENTIAL_PATHS[key][1] = list(set(file.read().splitlines()))

        # Call the function to initialize the arrays
        read_potential_sites()
        
        if do_sqli:
            website_to_test = POTENTIAL_PATHS["sqli"][1]
            cprint("\nTesting websites for SQL injection vulnerability...\n", 'yellow', file=sys.stderr)
            if not website_to_test:
                cprint("No websites found matching the dorks. Please adjust your search criteria.", 'red', file=sys.stderr)
            test_vulnerability_sqli(proxies)
        
        if do_xss:
            website_to_test = POTENTIAL_PATHS["xss"][1]
            cprint("\nTesting websites for XSS vulnerability...\n", 'yellow', file=sys.stderr)
            if not website_to_test:
                cprint("No websites found matching the dorks. Please adjust your search criteria.", 'red', file=sys.stderr)
            test_vulnerability_xss(proxies)
            
        cprint(banner_terminal_res , 'green', file=sys.stderr)

        if do_sqli and VULN_PATHS["sqli"][1]:
            cprint("The following targets are affected with SQLi:", "red", file=sys.stderr)
            for target in  VULN_PATHS["sqli"][1]:
                cprint(target, "red", file=sys.stderr)
                
        if do_xss and VULN_PATHS["xss"][1]:
            cprint("The following targets are affected with XSS:", "red", file=sys.stderr)
            for target in  VULN_PATHS["xss"][1]:
                cprint(target, "red", file=sys.stderr)
                
    finally:
        sys.stderr = orig_stdout
        f.close()   