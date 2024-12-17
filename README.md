# Prototype Pollution Scanner

## Overview

The **Prototype Pollution Scanner** is a specialized tool designed to automate the process of discovering subdomains for a given domain, verifying their availability, and testing them for **Prototype Pollution** vulnerabilities using a set of predefined payloads. This tool is essential for security researchers, penetration testers, and ethical hackers, enabling them to quickly scan subdomains and evaluate them for this specific security issue.

## Features

- **Subdomain Discovery**: Utilizes the `subfinder` tool to discover subdomains of a given domain.
- **Live Subdomain Check**: Verifies the existence of discovered subdomains by sending HTTP requests and checking their responses.
- **Vulnerability Testing**: Tests each live subdomain for **Prototype Pollution** vulnerabilities using a variety of crafted payloads.
- **Result Saving**: Allows users to save the list of vulnerable URLs to a specified file for further analysis or reporting.

## Prerequisites

Ensure the following dependencies are installed:

- **Python 3.x**: The script is written in Python 3, so ensure that Python is installed.
- **`requests` library**: Python HTTP library used for sending requests to subdomains.
- **`subfinder` tool**: Subdomain discovery tool used to find subdomains. Follow the instructions in the [subfinder GitHub repository](https://github.com/projectdiscovery/subfinder) to install it.

To install the required Python library (`requests`), use:

```bash
pip install requests
```

### Install `subfinder`:

Follow the installation instructions provided in the [subfinder documentation](https://github.com/projectdiscovery/subfinder).

## Usage

1. **Run the Script**: Execute the script using the following command in your terminal:

```bash
python prototypepollution.py
```

2. **Input Domain**: The script will prompt you to enter the domain name for which you want to discover subdomains.

3. **Subdomain Discovery**: The tool will use `subfinder` to discover subdomains associated with the provided domain.

4. **Live Subdomain Check**: The script will then check each discovered subdomain to determine if it's live by sending HTTP requests and evaluating the response.

5. **Vulnerability Testing**: Each live subdomain will be tested for **Prototype Pollution** vulnerabilities using a set of predefined payloads.

6. **Save Results**: After testing, if any vulnerable URLs are found, the script will prompt the user to save the results to a file. You can specify the file path where you want to store the vulnerable URLs.

   - If you choose not to save, the results will only be displayed in the terminal.
   - If you opt to save, the tool will ask for a file path and save the vulnerable URLs to the specified file.

## Prototype Pollution Vulnerability

### What is Prototype Pollution?

**Prototype Pollution** occurs when an attacker manipulates the prototype of a JavaScript object. This can lead to severe security issues, such as code execution, unexpected behavior, or denial of service (DoS). It typically exploits JavaScript's prototype inheritance system, which allows objects to inherit properties and methods from other objects.

In **Prototype Pollution** attacks, the attacker sends malicious input (e.g., specially crafted HTTP requests) that injects properties into the prototype of an object. This can cause the application to behave in unintended ways, leading to vulnerabilities such as:

- **Remote Code Execution (RCE)**: If an attacker controls the prototype, they might manipulate the execution flow.
- **Data Corruption**: Injected properties might overwrite or corrupt application data.
- **Denial of Service (DoS)**: Polluted prototypes can cause infinite loops or crashes in vulnerable applications.

#### Example of Prototype Pollution

Consider the following example of a malicious payload targeting an application vulnerable to prototype pollution:

```javascript
__proto__[test] = "test"
```

This payload attempts to inject a `test` property into the prototype of the object. If the application does not properly sanitize input, this could allow an attacker to modify the behavior of objects in the application, leading to potential exploitation.

### Vulnerability Payloads

The script uses a variety of predefined payloads to test subdomains for Prototype Pollution vulnerabilities. Some example payloads include:

- `?__proto__[test]=test`
- `?constructor.prototype.test=test`
- `?__proto__[test]={\"json\":\"value\"}`

These payloads are designed to exploit different variations of Prototype Pollution attacks in web applications.

## Script Functionality

### Subdomain Discovery

The tool uses the `subfinder` tool to perform subdomain discovery. `subfinder` is a popular open-source tool used for efficient subdomain enumeration. It collects subdomains from various public sources such as search engines, certificate transparency logs, and DNS records.

### Live Subdomain Check

Once the subdomains are discovered, the script checks whether each subdomain is live by sending HTTP requests. If a subdomain is responsive, it is flagged as "live" and is then tested for vulnerabilities.

### Vulnerability Testing

The script tests each live subdomain for potential vulnerabilities by sending the previously mentioned **Prototype Pollution** payloads. If the subdomain is vulnerable, it will be flagged as such and displayed to the user.

### Results Display

After testing, the script displays the results with color-coded outputs:

- **Red** for vulnerable subdomains.
- **Yellow** for errors or misconfigurations.
- **Green** for subdomains that are not vulnerable.

### File Saving

If vulnerabilities are found, the user will be prompted to save the results. If the user agrees, they are asked to specify the file path where the vulnerable URLs will be saved. The results are saved in a simple text format, and the file is named `vulnerable_urls.txt` by default.

## Example Output

```plaintext
Enter the domain to scan for subdomains: github.com
[+] Subdomains discovered for github.com:
    uber.github.com
    gist.github.com
    m.communication.github.com
    ...
[+] Live subdomains for github.com: ['uber.github.com', 'gist.github.com', ...]
[+] Testing payloads on uber.github.com
[+] No vulnerability found on uber.github.com with payload Wistia Embedded Video
[+] No vulnerability found on uber.github.com with payload William Bowling
...
[+] Vulnerable URLs found:
    http://uber.github.com?__proto__[test]=test
    http://gist.github.com?__proto__[test]=test
    ...
Do you want to save the vulnerable URLs to a file? (y/n): y
Enter the file path to save the vulnerable URLs: /path/to/save/vulnerable_urls.txt
[+] Vulnerable URLs saved to /path/to/save/vulnerable_urls.txt
```

## One-Liner Code Inspiration

This tool was inspired by the following one-liner code, which demonstrates the simplicity and power of payload injection for Prototype Pollution:

```bash
subfinder -d target.com -all -silent | \
httpx -silent -threads 100 | \
anew alive.txt && \
sed 's/$/\/?_proto_[testparam]=exploit\//' alive.txt | \
page-fetch -j 'window.testparam == "exploit" ? "[VULNERABLE]" : "[NOT VULNERABLE]"' | \
sed "s/ (I//g; s/)//g; s/JS //g" | \
grep "VULNERABLE"
```

This payload highlights the vulnerability in JavaScript objects when input is not properly sanitized. The script takes inspiration from this concept and expands it to multiple payloads for a comprehensive security check.

## Customization

- **Payloads**: You can add, modify, or remove payloads to test for other vulnerabilities or adjust the testing parameters.
- **Timeouts and Headers**: Adjust HTTP request timeouts and headers in the script if needed for specific use cases or more accurate tests.
- **Subdomain Discovery**: The tool uses `subfinder`, but you can replace it with other tools or methods if desired.

## Contact Me

Visit my Website to know me more [Karthik S Sathyan](https://karthik-s-sathyan.vercel.app).
