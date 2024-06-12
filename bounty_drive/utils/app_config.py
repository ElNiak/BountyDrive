
#########################################################################################
# Global variables
#########################################################################################
# PATH
GITHUB_FILE_PATH  = "reports/potential_github_sites.txt"
SQLI_FILE_PATH    = "reports/potential_sqli_sites.txt"
XSS_FILE_PATH     = "reports/potential_xss_sites.txt"
API_FILE_PATH     = "reports/potential_api_sites.txt"
WEB_FILE_PATH     = "reports/potential_web_sites.txt"
SECRET_FILE_PATH  = "reports/potential_secret_sites.txt"
DLPHP_FILE_PATH   = "reports/potential_dlphp_sites.txt"
BACKUP_FILE_PATH  = "reports/potential_backup_sites.txt"

POTENTIAL_PATHS = {
    "github": [GITHUB_FILE_PATH,[]], 
    "sqli": [SQLI_FILE_PATH,[]],
    "xss": [XSS_FILE_PATH,[]],
    "api": [API_FILE_PATH,[]],
    "web": [WEB_FILE_PATH,[]],
    "secret": [SECRET_FILE_PATH,[]],
    "dlphp": [DLPHP_FILE_PATH,[]],
    "backup": [BACKUP_FILE_PATH,[]]
}

VULN_SQLI_FILE_PATH    = "reports/vulnerable_sqli_sites.txt"
VULN_XSS_FILE_PATH     = "reports/vulnerable_xss_sites.txt"
VULN_API_FILE_PATH     = "reports/vulnerable_api_sites.txt"
VULN_WEB_FILE_PATH     = "reports/vulnerable_web_sites.txt"
VULN_SECRET_FILE_PATH  = "reports/vulnerable_secret_sites.txt"
VULN_DLPHP_FILE_PATH   = "reports/vulnerable_dlphp_sites.txt"
VULN_BACKUP_FILE_PATH  = "reports/vulnerable_backup_sites.txt"

VULN_PATHS = {
    "sqli": [VULN_SQLI_FILE_PATH,[]],
    "xss": [VULN_XSS_FILE_PATH,[]],
    "api": [VULN_API_FILE_PATH,[]],
    "web": [VULN_WEB_FILE_PATH,[]],
    "secret": [VULN_SECRET_FILE_PATH,[]],
    "dlphp": [VULN_DLPHP_FILE_PATH,[]],
    "backup": [VULN_BACKUP_FILE_PATH,[]]
}

# Constants for handling requests and delays
DEFAULT_EXTENSION    = ""
EXTENSION            = ""
DEFAULT_TOTAL_OUTPUT = 10 # TODO enforce
TOTAL_OUTPUT         = 10
DEFAULT_PAGE_NO      = 1
PAGE_NO              = 1
LANG                 ="en"
RECURSIVE            = True

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; U; Android 10; en-us; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 13729.56.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Mobile Safari/537.36'
]

# Initial delay and the factor by which the delay is multiplied
INITIAL_DELAY = 10   # Start with a 10-second delay
DELAY_FACTOR  = 2    # Double the delay each time 
MAX_DELAY     = 600  # Maximum delay of 10 minutes
REQUEST_DELAY = 5    # Base delay between requests in seconds
WAF_DELAY     = 600   # Delay for WAF detection in seconds

CURRENT_DELAY = INITIAL_DELAY # TODO add backoff timer