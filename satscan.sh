#!/bin/bash

# fuck u nigger
run_scanner() {
    local LOCATION_TYPE=$1
    local LOCATION=$2

    python3 - <<EOF
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, quote
import concurrent.futures
import sys
import json
from datetime import datetime

# Configuration
USER_AGENT = "Mozilla/5.0 (compatible; SatelliteScanner/1.0)"
REQUEST_TIMEOUT = 25
LOCATION = "$LOCATION"
LOCATION_TYPE = "$LOCATION_TYPE"
LOG_FILE = "satellite_log.txt"

# Validated satellite tracking sources
SOURCES = {
    "country": [
        f"https://www.n2yo.com/browse/?c={quote(LOCATION.lower())}",
        f"https://www.satbeams.com/satellites?country={quote(LOCATION.lower())}",
        f"https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=tle"
    ],
    "state": [
        f"https://www.satflare.com/search.asp?q={quote(LOCATION.replace(' ', '+'))}",
        f"https://www.satview.org/state.php?state={quote(LOCATION.replace(' ', '+'))}"
    ],
    "city": [
        f"https://www.satview.org/?location={quote(LOCATION.replace(' ', '+'))}",
        f"https://www.n2yo.com/passes/?s=&l={quote(LOCATION)}&r=50&d=1"
    ]
}

def log_satellite(sat_data):
    """Log all satellite data to file"""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(sat_data) + "\n")

def fetch_shodan_results(query):
    """Scrape Shodan results without API"""
    try:
        url = f"https://www.shodan.io/search?query={quote(query)}"
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml"
        }
        res = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if res.status_code != 200:
            return []
        
        soup = BeautifulSoup(res.text, 'html.parser')
        results = []
        
        # Extract IPs and ports from search results
        for result in soup.select('.search-result'):
            try:
                ip = result.select_one('.ip-str').get_text(strip=True)
                port = result.select_one('.port').get_text(strip=True)
                org = result.select_one('.org').get_text(strip=True) if result.select_one('.org') else "Unknown"
                results.append({
                    'ip': ip,
                    'port': port,
                    'org': org,
                    'source': 'shodan'
                })
            except:
                continue
        
        return results
    except Exception as e:
        print(f"[-] Shodan error: {str(e)}", file=sys.stderr)
        return []

def fetch_url(url, verify_ssl=True):
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5"
        }
        return requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=verify_ssl)
    except Exception as e:
        print(f"[-] Error fetching {url}: {str(e)}", file=sys.stderr)
        return None

def extract_satellites():
    sats = []
    print(f"\n[+] Searching for satellites over {LOCATION_TYPE}: {LOCATION}")
    
    # First check Shodan for satellite devices in this location
    shodan_query = f"satellite country:{LOCATION}" if LOCATION_TYPE == "country" else f"satellite region:{LOCATION}"
    shodan_results = fetch_shodan_results(shodan_query)
    for result in shodan_results:
        sats.append({
            'name': f"Shodan-{result['ip']}",
            'model': "Network Device",
            'org': result['org'],
            'details_url': f"http://{result['ip']}:{result['port']}",
            'ip': result['ip'],
            'port': result['port'],
            'source': 'shodan'
        })
    
    # Then check other sources
    for url in SOURCES.get(LOCATION_TYPE.lower(), []):
        # Special handling for Celestrak
        if "celestrak.org" in url:
            res = fetch_url(url, verify_ssl=False)
        else:
            res = fetch_url(url)
            
        if not res or res.status_code != 200:
            continue
        
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # N2YO parsing
        if "n2yo.com/browse" in url:
            for row in soup.select('tr.satelliteList'):
                try:
                    cols = row.find_all('td')
                    sats.append({
                        'name': cols[1].get_text(strip=True),
                        'model': cols[2].get_text(strip=True),
                        'details_url': urljoin(url, cols[1].find('a')['href']),
                        'source': 'n2yo'
                    })
                except:
                    continue
        
        # Satbeams parsing
        elif "satbeams.com" in url:
            for row in soup.select('table.satgrid tr:has(td)'):
                try:
                    cols = row.find_all('td')
                    sats.append({
                        'name': cols[0].get_text(strip=True),
                        'model': cols[1].get_text(strip=True),
                        'details_url': urljoin(url, cols[0].find('a')['href']),
                        'source': 'satbeams'
                    })
                except:
                    continue
        
        # Celestrak parsing (all active satellites)
        elif "celestrak.org" in url:
            tle_data = res.text.split('\n')
            for i in range(0, len(tle_data), 3):
                if i+2 >= len(tle_data):
                    break
                name = tle_data[i].strip()
                sats.append({
                    'name': name,
                    'model': "TLE Data",
                    'details_url': f"https://celestrak.org/satcat/search.php?NAME={quote(name)}",
                    'source': 'celestrak'
                })
        
        # Satflare parsing
        elif "satflare.com" in url:
            for row in soup.select('table#resultsTable tr:has(td)'):
                try:
                    cols = row.find_all('td')
                    sats.append({
                        'name': cols[0].get_text(strip=True),
                        'model': cols[1].get_text(strip=True),
                        'details_url': urljoin(url, cols[0].find('a')['href']),
                        'source': 'satflare'
                    })
                except:
                    continue
        
        # Satview parsing
        elif "satview.org" in url:
            for item in soup.select('.satellite-item, .pass-item'):
                try:
                    sats.append({
                        'name': item.select_one('.sat-name, .satellite').get_text(strip=True),
                        'model': item.select_one('.sat-model, .model').get_text(strip=True),
                        'details_url': urljoin(url, item.find('a')['href']),
                        'source': 'satview'
                    })
                except:
                    continue
    
    print(f"[+] Found {len(sats)} satellites")
    return sats

def scan_satellite(sat):
    result = {
        'name': sat['name'],
        'model': sat.get('model', 'Unknown'),
        'source': sat.get('source', 'unknown'),
        'timestamp': datetime.now().isoformat(),
        'location': LOCATION,
        'location_type': LOCATION_TYPE,
        'control_urls': [],
        'ips': [sat['ip']] if 'ip' in sat else [],
        'ports': [sat['port']] if 'port' in sat else [],
        'vulnerabilities': [],
        'credentials': [],
        'org': sat.get('org', '')
    }
    
    # Skip detailed scanning for TLE data and Shodan results (already have IPs)
    if sat.get('model') == "TLE Data" or sat.get('source') == 'shodan':
        log_satellite(result)
        return result
    
    # Get satellite details page
    details = fetch_url(sat.get('details_url', ''))
    if not details or details.status_code != 200:
        log_satellite(result)
        return result
    
    soup = BeautifulSoup(details.text, 'html.parser')
    
    # Find control interfaces in documentation
    for link in soup.find_all('a', href=True):
        href = link['href'].lower()
        if any(x in href for x in ['admin', 'login', 'control', 'panel', 'cgi-bin']):
            result['control_urls'].append(urljoin(sat['details_url'], link['href']))
    
    # Find IPs in technical docs
    tech_text = ' '.join([p.get_text() for p in soup.select('p, pre, code, td')])
    result['ips'] += list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', tech_text)))
    result['ports'] += list(set(re.findall(r'port\s*[=:]\s*(\d{2,5})', tech_text, re.I)))
    
    # Find vulnerabilities
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
    result['vulnerabilities'] = cve_pattern.findall(tech_text)
    
    # Find credentials in documentation
    cred_matches = re.findall(r'(user(name)?|login):\s*(\S+).*?(pass(word)?|pwd):\s*(\S+)', tech_text, re.I)
    for match in cred_matches:
        result['credentials'].append(f"{match[2]}:{match[5]}")
    
    # Log all results
    log_satellite(result)
    return result

def main():
    # Clear previous log file
    open(LOG_FILE, 'w').close()
    
    satellites = extract_satellites()
    if not satellites:
        print("[-] No satellites found for this location")
        return False
    
    print("[+] Scanning for vulnerabilities...")
    vulnerable_sats = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_satellite, sat) for sat in satellites]
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result['vulnerabilities'] or result['credentials']:
                vulnerable_sats.append(result)
            print(f"\rProgress: {i+1}/{len(satellites)}", end='')
    
    print(f"\n\n[+] All results saved to {LOG_FILE}")
    
    if not vulnerable_sats:
        print("[-] No vulnerable satellites found")
        return False
    
    print("\n[+] Vulnerable Satellites Found:")
    for sat in vulnerable_sats:
        print(f"\n\033[1;33m{sat['name']} ({sat['model']})\033[0m")
        print(f"Source: {sat['source']}")
        if sat['ips']:
            print(f"IP Addresses: {', '.join(sat['ips'])}")
        if sat['ports']:
            print(f"Ports: {', '.join(sat['ports'])}")
        if sat['control_urls']:
            print("Control Interfaces:")
            for url in sat['control_urls']:
                print(f" - \033[1;34m{url}\033[0m")
        if sat['vulnerabilities']:
            print("Known Vulnerabilities:")
            for vuln in sat['vulnerabilities']:
                print(f" - \033[1;31m{vuln}\033[0m")
        if sat['credentials']:
            print("Discovered Credentials:")
            for cred in sat['credentials']:
                print(f" - \033[1;32m{cred}\033[0m")
    
    return True

if __name__ == "__main__":
    main()
EOF
}

# stfu just do it
echo -e "\033[1;36mSatellite Vulnerability Scanner v3.0\033[0m"
echo -e "\033[1;33m(Now with Shodan integration and comprehensive logging)\033[0m\n"

read -p "Enter target country: " COUNTRY
run_scanner "country" "$COUNTRY"

if [ $? -ne 0 ]; then
    read -p "No satellites found at country level. Enter state/province: " STATE
    run_scanner "state" "$STATE"
    
    if [ $? -ne 0 ]; then
        read -p "No satellites found at state level. Enter city: " CITY
        run_scanner "city" "$CITY"
        
        if [ $? -ne 0 ]; then
            echo -e "\n[-] No satellites found at any location level"
        fi
    fi
fi
