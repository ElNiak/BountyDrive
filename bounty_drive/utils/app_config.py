#########################################################################################
# Global variables
#########################################################################################
# PATH
GITHUB_FILE_PATH = "reports/potential_github_sites.txt"
SQLI_FILE_PATH = "reports/potential_sqli_sites.txt"
XSS_FILE_PATH = "reports/potential_xss_sites.txt"
API_FILE_PATH = "reports/potential_api_sites.txt"
WEB_FILE_PATH = "reports/potential_web_sites.txt"
SECRET_FILE_PATH = "reports/potential_secret_sites.txt"
PHP_FILE_PATH = "reports/potential_dowload-php_sites.txt"
BACKUP_FILE_PATH = "reports/potential_backup_sites.txt"

POTENTIAL_PATHS = {
    "github": [GITHUB_FILE_PATH, set()],
    "sqli": [SQLI_FILE_PATH, set()],
    "xss": [XSS_FILE_PATH, set()],
    "api": [API_FILE_PATH, set()],
    "web": [WEB_FILE_PATH, set()],
    "secret": [SECRET_FILE_PATH, set()],
    "dowload-php": [PHP_FILE_PATH, set()],
    "backup": [BACKUP_FILE_PATH, set()],
}

VULN_SQLI_FILE_PATH = "reports/vulnerable_sqli_sites.txt"
VULN_XSS_FILE_PATH = "reports/vulnerable_xss_sites.txt"
VULN_API_FILE_PATH = "reports/vulnerable_api_sites.txt"
VULN_WEB_FILE_PATH = "reports/vulnerable_web_sites.txt"
VULN_SECRET_FILE_PATH = "reports/vulnerable_secret_sites.txt"
VULN_PHP = "reports/vulnerable_dowload-php_sites.txt"
VULN_BACKUP_FILE_PATH = "reports/vulnerable_backup_sites.txt"

VULN_PATHS = {
    "sqli": [VULN_SQLI_FILE_PATH, set()],
    "xss": [VULN_XSS_FILE_PATH, set()],
    "api": [VULN_API_FILE_PATH, set()],
    "web": [VULN_WEB_FILE_PATH, set()],
    "secret": [VULN_SECRET_FILE_PATH, set()],
    "dowload-php": [VULN_PHP, set()],
    "backup": [VULN_BACKUP_FILE_PATH, set()],
}

# Constants for handling requests and delays
DEFAULT_EXTENSION = ""
EXTENSION = ""
DEFAULT_TOTAL_OUTPUT = 10  # TODO enforce
TOTAL_OUTPUT = 10
DEFAULT_PAGE_NO = 1
PAGE_NO = 1
LANG = "en"
RECURSIVE = True

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
]


# Initial delay and the factor by which the delay is multiplied
INITIAL_DELAY = 2  # Start with a 10-second delay
DELAY_FACTOR = 2  # Double the delay each time
MAX_DELAY = 600  # Maximum delay of 10 minutes
REQUEST_DELAY = 15  # Base delay between requests in seconds
WAF_DELAY = 600  # Delay for WAF detection in seconds

CURRENT_DELAY = INITIAL_DELAY  # TODO add backoff timer
