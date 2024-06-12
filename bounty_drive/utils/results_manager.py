import threading

from termcolor import cprint
from utils.app_config import *
             
#########################################################################################
# File writing functions
#########################################################################################

# Define file paths
# Initialize locks for thread-safe file writing
# TODO make more modular


lock_git     = threading.Lock()
lock_sqli    = threading.Lock()
lock_xss     = threading.Lock()
lock_api     = threading.Lock()
lock_web     = threading.Lock()
lock_secret  = threading.Lock()
lock_dlphp   = threading.Lock()
lock_backup  = threading.Lock()


# Thread-safe addition to results lists
def safe_add_result(result, 
                    websites_sqli=None, 
                    websites_xss=None,
                    websites_vuln=None, 
                    websites_api=None, 
                    websites_secret=None, 
                    websites_dlphp=None, 
                    websites_backup=None, 
                    github_websites=None):
    # TODO category not working, all go to xss
    category, urls = result
    if urls:
        cprint(f"Adding {len(urls)} URLs to {category} list...", 'blue', file=sys.stderr)
        for url in urls:
            if url:
                if "https://www.google.com/sorry/" not in url:
                    if "github.com" in url:
                        with lock_git:
                            with open(GITHUB_FILE_PATH, "a") as file:
                                file.write(url + "\n")
                            github_websites.add(url)
                    elif category == "sqli":
                        with lock_sqli:  # Ensure thread-safe write operation
                            with open(SQLI_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_sqli.add(url)  # Optionally maintain the set
                    elif category == "xss":
                        with lock_xss:  # Ensure thread-safe write operation
                            with open(XSS_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_xss.add(url)  # Optionally maintain the set
                    elif category == "web":
                        with lock_web:  # Ensure thread-safe write operation
                            with open(WEB_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_vuln.add(url)  # Optionally maintain the set
                    elif category == "api":
                        with lock_api:  # Ensure thread-safe write operation
                            with open(API_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_api.add(url)  # Optionally maintain the set
                    elif category == "secret":
                        with lock_secret:  # Ensure thread-safe write operation
                            with open(SECRET_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_secret.add(url)  # Optionally maintain the set
                    elif category == "download-php":
                        with lock_dlphp:  # Ensure thread-safe write operation
                            with open(DLPHP_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_dlphp.add(url)  # Optionally maintain the set
                    elif category == "backup":
                        with lock_backup:  # Ensure thread-safe write operation
                            with open(BACKUP_FILE_PATH, "a") as file:  # Open file in append mode
                                file.write(url + "\n")  # Write URL to file
                            websites_backup.add(url)  # Optionally maintain the set
