import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import re

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.vulnerabilities = []

    def crawl(self, url):
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith("http") and self.target_url in href:
                    if href not in self.visited_urls:
                        self.visited_urls.add(href)
                        self.crawl(href)
        except:
            pass

    def check_sql_injection(self, url):
        test_url = url + "'"
        try:
            r = requests.get(test_url, timeout=5)
            errors = ["you have an error in your sql syntax", "mysql", "syntax error"]
            for error in errors:
                if error in r.text.lower():
                    self.report_vulnerability({
                        "type": "SQL Injection",
                        "url": test_url
                    })
        except:
            pass

    def check_xss(self, url):
        payload = "<script>alert(1)</script>"
        test_url = url + "?q=" + payload
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                self.report_vulnerability({
                    "type": "XSS",
                    "url": test_url
                })
        except:
            pass

    def check_sensitive_info(self, url):
        try:
            r = requests.get(url, timeout=5)
            if re.search(r"apikey|password|secret|token", r.text, re.I):
                self.report_vulnerability({
                    "type": "Sensitive Info Disclosure",
                    "url": url
                })
        except:
            pass

    def report_vulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)
        print("[VULNERABILITY FOUND]")
        for k, v in vulnerability.items():
            print(f"{k}: {v}")
        print()

    def scan(self):
        print(f"Starting security scan of {self.target_url}")
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
        return self.vulnerabilities

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.scan()
    print(f"Scan Complete! Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
