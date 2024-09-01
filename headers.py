#!/usr/bin/env python3

import requests
import json
import argparse
from tabulate import tabulate
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

# Define colors
class Colors:
    INFO = Fore.BLUE
    OK = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL

# Define headers to check
SECURITY_HEADERS = {
    'X-XSS-Protection': 'deprecated',
    'X-Frame-Options': 'warning',
    'X-Content-Type-Options': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Referrer-Policy': 'warning',
    'Expect-CT': 'deprecated',
    'Permissions-Policy': 'warning',
    'Cross-Origin-Embedder-Policy': 'warning',
    'Cross-Origin-Resource-Policy': 'warning',
    'Cross-Origin-Opener-Policy': 'warning'
}

def fetch_headers(url, method='HEAD', verify_ssl=True):
    try:
        response = requests.request(method, url, verify=verify_ssl)
        return response.headers
    except requests.RequestException as e:
        print(f"{Colors.ERROR}[!] Error fetching headers: {e}")
        return None

def check_security_headers(headers):
    results = {'present': {}, 'missing': []}

    for header, status in SECURITY_HEADERS.items():
        header_lower = header.lower()
        if header_lower in headers:
            results['present'][header] = headers[header_lower]
        else:
            results['missing'].append(header)
    
    return results

def print_results(url, results, json_output):
    if json_output:
        print(json.dumps(results, indent=2))
    else:
        # Print title in large ASCII art
        ascii_art = pyfiglet.figlet_format("Scudent", font="big")
        print(f"{Colors.BOLD}{Colors.INFO}{ascii_art}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Checked URL:{Colors.INFO} {url}")

        # Format data for display
        present_data = []
        for header, value in results['present'].items():
            color = Colors.OK if SECURITY_HEADERS.get(header) != 'deprecated' else Colors.WARNING
            present_data.append([color + header + Colors.RESET, value])

        missing_data = [[Colors.ERROR + header + Colors.RESET] for header in results['missing']]

        # Print results in table format
        if present_data:
            print(f"\n{Colors.BOLD}Present Security Headers:")
            print(tabulate(present_data, headers=['Header', 'Value'], tablefmt='grid', maxcolwidths=[30, 50]))

        if missing_data:
            print(f"\n{Colors.BOLD}Missing Security Headers:")
            print(tabulate(missing_data, headers=['Header'], tablefmt='grid'))

def main():
    parser = argparse.ArgumentParser(description="Check security headers of a web server.")
    parser.add_argument('target', help="Target URL (e.g., http://example.com)")
    parser.add_argument('-m', '--method', choices=['HEAD', 'GET'], default='HEAD', help="HTTP method to use")
    parser.add_argument('-d', '--disable-ssl', action='store_true', help="Disable SSL certificate verification")
    parser.add_argument('-j', '--json', action='store_true', help="Output results in JSON format")
    
    args = parser.parse_args()
    url = args.target
    method = args.method
    verify_ssl = not args.disable_ssl

    headers = fetch_headers(url, method, verify_ssl)
    if headers:
        results = check_security_headers(headers)
        print_results(url, results, args.json)

if __name__ == "__main__":
    main()
