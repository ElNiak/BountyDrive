<h1 align="center">BountyDrive</h1>
<p align="center">Bug Orientation tool Utilizing Novel Tactics Yields Dorking Research Implementing Vulnerability Exploitation </p><br>
<div align="center">
<img src="https://forthebadge.com/images/badges/made-with-python.svg" >
</div>

## Installation
```bash
make

```
## Usage
```bash
python3 bounty_drive.py
```

```bash
Please specify the website extension(eg- .in,.com,.pk) [default: ] -----> 
Do you want to restrict search to subdomain present in target.txt ? [default: true (vs false)] -----> true
Please specify the total no. of websites you want [default: 10] ----> 
From which Google page you want to start(eg- 1,2,3) [default: 1] ----> 
Do you want to do the Google dorking scan phase ? [default: true (vs false)] ----> 
Do you want to do the Github dorking scan phase ? [default: true (vs false)] ----> false
Do you want to test for XSS vulnerability ? [default: true (vs false)] ----> true
Do you want to encode XSS payload ? [default: true (vs false)] ----> false
Do you want to fuzz XSS payload ? [default: true (vs false)] ----> true
Do you want to test blind XSS payload ? [default: true (vs false)] ----> false
Do you want to test for SQLi vulnerability ? [default: true (vs false)] ----> false
Extension: , Total Output: 10, Page No: 1, Do Google Dorking: True, Do Github Dorking False
```

## Tips
Use Google hacking database(https://www.exploit-db.com/google-hacking-database) for good sqli dorks.

## Proxies


Free proxies from free-proxy-list.net
Updated at 2024-02-18 15:32:02 UTC.

TODO: we should proxy proxy chains

# HAPPY HUNTING


# Ressource:
https://raw.githubusercontent.com/darklotuskdb/SSTI-XSS-Finder/main/Payloads.txt
https://github.com/nu11secur1ty/nu11secur1ty/blob/master/kaylogger/nu11secur1ty.py
https://github.com/Ishanoshada/GDorks/blob/main/dorks.txt
https://github.com/BullsEye0/google_dork_list/tree/master
https://github.com/Ishanoshada/GDorks/tree/main
https://github.com/anmolksachan/CrossInjector/tree/main?tab=readme-ov-file
https://github.com/Gualty/asqlmap
https://github.com/bambish/ScanQLi/blob/master/scanqli.py

https://github.com/0MeMo07/URL-Seeker

https://github.com/obheda12/GitDorker/blob/master/GitDorker.py
https://medium.com/@dub-flow/the-easiest-way-to-find-cves-at-the-moment-github-dorks-29d18b0c6900
https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets
https://github.com/gwen001/github-search
https://obheda12.medium.com/gitdorker-a-new-tool-for-manual-github-dorking-and-easy-bug-bounty-wins-92a0a0a6b8d5
https://github.com/spekulatius/infosec-dorks

https://github.com/RevoltSecurities/Subdominator

# TODO
add a vulnerable wordpress plugin and then dork to find vulnerable wordpress sites