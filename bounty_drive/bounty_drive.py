#/usr/bin/python3
import argparse
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

    
from attacks.dorks.google_dorking import load_google_dorks_and_search
from attacks.sqli.sqli import test_vulnerability_sqli
from attacks.xss.xss import test_vulnerability_xss
from utils.banner import load_animation
from utils.proxies import setup_proxies
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

def get_user_arguments_input():
    """
    Collect user input for website extension, total output, and starting page number, with default values.
    """
    parser = argparse.ArgumentParser(description='Collect user input for scanning websites.')

    parser.add_argument('--extension', type=str, default=DEFAULT_EXTENSION, help='Website extension (default: .com)')
    parser.add_argument('--subdomain', type=str, default="true", help='Restrict search to subdomain present in target.txt (default: true)')
    parser.add_argument('--total_output', type=int, default=DEFAULT_TOTAL_OUTPUT, help='Total number of websites to scan (default: 10)')
    parser.add_argument('--page_no', type=int, default=DEFAULT_PAGE_NO, help='Starting page number for Google search (default: 1)')
    
    parser.add_argument('--do_dorking_google', type=str, default="true", help='Perform Google dorking scan phase (default: true)')
    parser.add_argument('--do_dorking_github', type=str, default="true", help='Perform Github dorking scan phase (default: true)')
    
    parser.add_argument('--do_xss', type=str, default="true", help='Test for XSS vulnerability (default: true)')
    parser.add_argument('--do_encode_xss', type=str, default="true", help='Encode XSS payload (default: true)')
    parser.add_argument('--do_fuzzing_xss', type=str, default="true", help='Fuzz XSS payload (default: true)')
    parser.add_argument('--do_blind_xss', type=str, default="true", help='Test blind XSS payload (default: true)')
    
    parser.add_argument('--do_sqli', type=str, default="true", help='Test for SQLi vulnerability (default: true)')

    args = parser.parse_args()

    extension = args.extension
    subdomain = args.subdomain.lower() == "true"
    total_output = args.total_output
    page_no = args.page_no
    
    do_dorking_google = args.do_dorking_google.lower() == "true"
    do_dorking_github = args.do_dorking_github.lower() == "true"
    
    do_xss = args.do_xss.lower() == "true"
    encode_xss = args.do_encode_xss.lower() == "true"
    fuzzing_xss = args.do_fuzzing_xss.lower() == "true"
    blind_xss = args.do_blind_xss.lower() == "true"
    
    do_sqli = args.do_sqli.lower() == "true"

    if subdomain:
        with open("target.txt", "r") as file:
            subdomain_list = file.read().splitlines()
        cprint(f"Subdomains: {subdomain_list}", 'green', file=sys.stderr)

    cprint(f"Extension: {extension}, Total Output: {total_output}, Page No: {page_no}, Do Google Dorking: {do_dorking_google}, Do Github Dorking {do_dorking_github}", 'green', file=sys.stderr)
    
    return extension, do_dorking_google, do_dorking_github, do_sqli, do_xss

def get_user_input():
    """
    Collect user input for website extension, total output, and starting page number, with default values.
    """
    extension    = input(colored(f"Please specify the website extension(eg- .in,.com,.pk) [default: {DEFAULT_EXTENSION}] -----> ", 'cyan')) or DEFAULT_EXTENSION # TODO
    subdomain    = input(colored(f"Do you want to restrict search to subdomain present in target.txt ? [default: true (vs false)] -----> ", 'cyan')) or "true"
    total_output = input(colored(f"Please specify the total no. of websites you want [default: {DEFAULT_TOTAL_OUTPUT}] ----> ", 'cyan')) or DEFAULT_TOTAL_OUTPUT
    page_no      = input(colored(f"From which Google page you want to start(eg- 1,2,3) [default: {DEFAULT_PAGE_NO}] ----> ", 'cyan')) or DEFAULT_PAGE_NO
    
    do_dorking_google   = input(colored(f"Do you want to do the Google dorking scan phase ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_dorking_github   = input(colored(f"Do you want to do the Github dorking scan phase ? [default: false (vs true)] ----> ", 'cyan')) or "false"
    
    do_xss           = input(colored(f"Do you want to test for XSS vulnerability ? [default: true (vs false)] ----> ", 'cyan')) or "true"
    do_xss              = True if do_xss.lower() == "true" else False 
    if do_xss:
        do_encode_xss    = input(colored(f"Do you want to encode XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
        do_fuzzing_xss   = input(colored(f"Do you want to fuzz XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
        do_blind_xss     = input(colored(f"Do you want to test blind XSS payload ? [default: true (vs false)] ----> ", 'cyan')) or "true"
        ENCODE_XSS       = True if do_encode_xss.lower() == "true" else False
        FUZZ_XSS         = True if do_fuzzing_xss.lower() == "true" else False
        BLIND_XSS        = True if do_blind_xss.lower() == "true" else False
    
    do_sqli         = input(colored(f"Do you want to test for SQLi vulnerability ? [default: false (vs true)] ----> ", 'cyan')) or "false"
    
    # Ensure numeric inputs are correctly converted to integers
    TOTAL_OUTPUT = int(total_output)
    PAGE_NO      = int(page_no)
    do_dorking_google   = True if do_dorking_google.lower() == "true" else False
    do_dorking_github   = True if do_dorking_github.lower() == "true" else False
    subdomain           = True if subdomain.lower() == "true" else False
    
    
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
            extension, do_dorking_google, do_dorking_github, do_sqli, do_xss = get_user_arguments_input()
        else:
            extension, do_dorking_google, do_dorking_github, do_sqli, do_xss = get_user_input()
            
        proxies = setup_proxies()
        cprint("Number of proxies: " + str(len(proxies)), 'green', file=sys.stderr)
        
        if do_dorking_google:
            cprint("\nStarting Google dorking scan phase...\n", 'yellow', file=sys.stderr)
            load_google_dorks_and_search(extension, proxies)
            
        if do_dorking_github:
            cprint("\nStarting Github dorking scan phase...\n", 'yellow', file=sys.stderr)
            raise NotImplementedError("Github dorking scan phase not implemented yet")
            load_github_dorks_and_search(extension, proxies)  
        
        def read_potential_sites():
            for key, value in POTENTIAL_PATHS.items():
                if not os.path.exists(value[0]):
                    with open(value[0], 'w') as file:
                        file.write('')
                with open(value[0], 'r') as file:
                    POTENTIAL_PATHS[key][1] = list(set(file.read().splitlines()))

        # Call the function to initialize the arrays
        read_potential_sites()
        
        if do_sqli:
            raise NotImplementedError("SQLi phase not implemented yet")
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
            raise NotImplementedError("SQLi phase not implemented yet")
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