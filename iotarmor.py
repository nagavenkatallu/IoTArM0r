# 144 lines

#!/usr/bin/python3
import argparse
import nmap
import censys.certificates
import censys.ipv4
import zoomeye.sdk as zoomeye
import shodan
import onyphe
import greynoise

from termcolor import colored

# IoT4rMor[IoTArmor] ASCII art
IoT4rMor_art = '''
       _______
    .-"       "-.
  /             \\
| / /  |       \\ \\
\\ \\/   ;       \\ \\
 \\     /        | |
  \\   |        / /
   `._;       /_/  '''
print(colored(IoT4rMor_art, 'cyan'))

def nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-p 80,443')
    open_ports = []
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    open_ports.append(port)
    return open_ports

def censys_cert_search(ip_address, api_id, api_secret):
    certificates = censys.certificates.CensysCertificates(api_id, api_secret)
    search_results = certificates.search(ip_address, fields=['parsed.subject_dn'])
    if len(search_results) > 0:
        for cert in search_results:
            print(colored(f'Certificate found: {cert["parsed.subject_dn"]}', 'green'))
    else:
        print(colored('No certificate found.', 'red'))

def censys_ipv4_search(ip_address, api_id, api_secret):
    ipv4 = censys.ipv4.CensysIPv4(api_id, api_secret)
    search_results = ipv4.view(ip_address)
    if 'metadata' in search_results:
        metadata = search_results['metadata']
        print(colored(f'Organization: {metadata["organization"]}', 'green'))
        print(colored(f'Operating system: {metadata["os"]}', 'green'))
    else:
        print(colored('No metadata found.', 'red'))

def zoomeye_scan(target, username, password):
    zm = zoomeye.ZoomEye()
    zm.user_login(username=username, password=password)
    query = f"ip:{target}"
    zoomeye_result = zm.dork_search(query)
    if zoomeye_result:
        print(colored(f"ZoomEye results for {target}:", 'green')) # fixed reference to target
        for i, hit in enumerate(zoomeye_result['matches']): # added ['matches'] to iterate over results
            print(colored(f"Hit #{i+1}:", 'green'))
            print(colored(f"Title: {hit['title']}", 'green')) # removed default value for title
            print(colored(f"Description: {hit['description']}", 'green'))
            print(colored(f"Web URL: {hit['site']}", 'green'))
            print(colored(f"App URL: {hit['app']['url']}", 'green')) # fixed nested reference to url
            print(colored(f"Port: {hit['port']}", 'green')) # changed reference to 'port' key
            print(colored(f"Service: {hit['service']}", 'green')) # changed reference to 'service' key
            print(colored(f"Banner: {hit.get('banner', 'N/A')}", 'green')) # added default value for banner
    else:
        print(colored(f"No ZoomEye results found for {args.target}.", 'red'))


def shodan_scan(target, api_key):
    shodan_api = shodan.Shodan(api_key)
    try:
        shodan_result = shodan_api.host(target)
    except shodan.exception.APIError as e:
        print(colored(f"Shodan API error: {e}", 'red'))
    print(colored(f"Shodan results for {args.target}:", 'green'))
    print(colored(f"Organization: {shodan_result.get('org', 'N/A')}", 'green'))
    print(colored(f"Operating system: {shodan_result.get('os', 'N/A')}", 'green'))
    print(colored(f"Hostnames: {', '.join(shodan_result.get('hostnames', []))}", 'green'))
    print(colored(f"Country: {shodan_result.get('country_name', 'N/A')} ({shodan_result.get('country_code', 'N/A')})", 'green'))
    print(colored(f"City: {shodan_result.get('city', 'N/A')}", 'green'))

def onyphe_scan(target, api_key):
    client = onyphe.Onyphe(api_key=api_key)
    query = f"ip:{target}"
    results = client.search(query=query)
    if results['total'] > 0:
        for result in results['data']:
            print(colored(f"Onyphe: {result['ip']} - {result['port']} - {result['module']}", 'green'))
    else:
        print(colored('No results found on Onyphe.', 'red'))
def main():
# Command-line arguments
    parser = argparse.ArgumentParser(description='H4ckS1ght - A reconnaissance tool')
    parser.add_argument('-t', '--target', help='Target IP address', required=True)
    parser.add_argument('-u', '--username', help='ZoomEye username')
    parser.add_argument('-p', '--password', help='ZoomEye password')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API secret')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--onyphe-key', help='Onyphe API key')
    args = parser.parse_args()
    target = args.target
    print(colored(f"Scanning ports 80 and 443 on {args.target}...", 'cyan'))
    open_ports = nmap_scan(target)
    if len(open_ports) > 0:
        print(colored(f"Open ports: {', '.join(map(str, open_ports))}", 'green'))
    else:
        print(colored('No open ports found.', 'red'))
    if args.censys_id and args.censys_secret:
        print(colored(f"Searching Censys for certificates issued to {args.target}...", 'cyan'))
        censys_cert_search(target, args.censys_id, args.censys_secret)
    else:
        print(colored('Censys API ID and secret not provided. Skipping certificate search.', 'yellow'))
    if args.censys_id and args.censys_secret:
        print(colored(f"Searching Censys for metadata on {args.target}...", 'cyan'))
        censys_ipv4_search(target, args.censys_id, args.censys_secret)
    else:
        print(colored('Censys API ID and secret not provided. Skipping metadata search.', 'yellow'))
    if args.username and args.password:
        print(colored(f"Searching ZoomEye for information on {args.target}...", 'cyan'))
        zoomeye_scan(target, args.username, args.password)
    else:
        print(colored('ZoomEye username and password not provided. Skipping search.', 'yellow'))

    if args.shodan_key:
        print(colored(f"Searching Shodan for information on {args.target}...", 'cyan'))
        shodan_scan(target, args.shodan_key)
    else:
        print(colored('Shodan API key not provided. Skipping search.', 'yellow'))

    if args.onyphe_key:
        print(colored(f"Searching Onyphe for information on {args.target}...", 'cyan'))
        onyphe_scan(target, args.onyphe_key)
    else:
        print(colored('Onyphe API key not provided. Skipping search.', 'yellow'))
if name == 'main':
    main()