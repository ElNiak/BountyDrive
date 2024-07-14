<h1 align="center">BountyDrive</h1>
<p align="center">Bug Orientation tool Utilizing Novel Tactics Yields Dorking Research Implementing Vulnerability Exploitation </p><br>
<div align="center">
<img src="https://forthebadge.com/images/badges/made-with-python.svg" >
</div>

## Introduction:

BountyDrive is a comprehensive tool designed for penetration testers and cybersecurity researchers. It integrates various modules for performing attacks, reporting, and managing VPN/proxy settings, making it an indispensable asset for any security professional.

## Features:
- **Automation**: Automate the process of finding vulnerabilities.
- **Dorking**: Automate Google, GitHub, and Shodan dorking to find vulnerabilities.
- **Web Crawling**: Crawl web pages to collect data.
- **Scanning**: Perform different types of vulnerability scans.
- **SQL Injection**: Execute SQL injection attacks.
- **XSS**: Perform Cross-Site Scripting attacks.
- **WAF Bypassing**: Techniques to bypass Web Application Firewalls.
- **Reporting**: Generate detailed reports of findings.
- **VPN/Proxies Management**: Seamlessly switch between different VPN services and proxies to anonymize your activities.

## Python

- **Python3** is natively supported:
    
```bash
# Dorking process time with 9 threads:


# Crawling process time with 9 threads:


# XSS process time with 9 threads:
  

```

- **pypy3 Support**: Use pypy3 to speed up the execution of the tool:

```bash
# Dorking process time with 9 threads:


# Crawling process time with 9 threads:


# XSS process time with 9 threads:

```

- **numba Support**: Use numba to speed up the execution of the tool:

```bash
# Dorking process time with 9 threads:


# Crawling process time with 9 threads:


# XSS process time with 9 threads:


```

## Installation:

### Packages:

```bash
# For reCAPTCHA
sudo apt-get install portaudio19-dev

```

### Pre-Commit:

```bash
python3 -m pip install pre-commit
pre-commit installed at .git/hooks/pre-commit
mypy bounty_drive/
```

### Classical:

```bash
sudo apt-get install python3 python3-dev python3-venv
python3 --version
# Python 3.10.12
```

```bash
python3 -m venv python3-venv
source python3-venv/bin/activate
python3 -m pip install -U pip wheel
python3 -m pip install -r requirements.txt
```

Update `config.ini`

Run with `python3 bounty_drive.py`

### PyPy: 

Not ready - SEGFAULT in some libs (urllib3, cryptography downgraded).

Install PyPy from [here](https://doc.pypy.org/en/latest/install.html)

Package compatible with PyPy are in `requirements_pypy.txt`
* http://packages.pypy.org/
* https://doc.pypy.org/en/latest/cpython_differences.html

```bash
sudo apt-get install pypy3 pypy3-dev pypy3-venv
pypy3 --version
# Python 3.9.19 (7.3.16+dfsg-2~ppa1~ubuntu20.04, Apr 26 2024, 13:32:24)
# [PyPy 7.3.16 with GCC 9.4.0]
```

```bash
pypy3 -m venv pypy3-venv
source pypy3-venv/bin/activate
pypy3 -m pip install -U pip wheel
pypy3 -m pip install -r requirements_pypy.txt
```

pdate `config.ini`

Run with `pypy3 bounty_drive.py`


## Usage:

```bash
# update configs/config.ini
python3 bountry_drive.py [config_file]
pypy3   bountry_drive.py [config_file]
```

## VPN/Proxies Management:

* NordVPN: Switch between NordVPN servers.
* Proxies: Use different proxy lists to route your traffic.

## Contributing:

We welcome contributions from the community. To contribute:

* Fork the repository.
* Create a new branch for your feature or bugfix.
* Commit your changes and push the branch.
* Create a pull request detailing your changes.

## Ressource:

* https://github.com/Karmaz95/crimson/blob/master/words/exp/special_chars.txt
* https://github.com/hahwul/dalfox
* https://github.com/mandiant/PwnAuth

## TODOs:

Also watch module for more specfic TODOs:

* Implement API/SCAN/SQLi/SSTI
* https://python-hyperscan.readthedocs.io/en/latest/usage/ for regex
* Improving Selenium for WAF bypass and perform attack (check for edge driver seems better)
* Add a vulnerable wordpress plugin and then dork to find vulnerable wordpress sites
* Create class for each attack
* Change the color used
* Implement the login module in website to attacks with Cookie & co.
* Add similar page detector to avoid duplicate crawling
* implement asyncio
* robot.txt: | http-robots.txt: 69 disallowed entries (15 shown)
| /_admrus/ /_admrusr/ /publicite/www/delivery/ 
| /signaler-contenu-illicite.html* /desabo/ /optins/preferences/ /php/ /php/ajax/* 
| /feuilletables/ /iframe/ /newsletters/ 
|_/jeu-nouveau-rustica-bien-etre/ /concours/ /popunder/ /popup/
* https://github.com/dwisiswant0/findom-xss/blob/master/findom-xss.sh