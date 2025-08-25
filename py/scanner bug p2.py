import requests
from bs4 import BeautifulSoup
import re
import sys
import csv

class P2VulnerabilityScanner:
    def __init__(self, urls_file):
        self.urls_file = urls_file
        self.vulnerabilities = []

        # پیلودها و checks پایه برای P2
        self.payloads = {
            "OTP Bypass": ["?otp=123456", "?otp=test"],  # شناسایی endpoint
            "Privilege Escalation": ["/admin", "/dashboard", "?role=admin"],
            "CORS Misconfiguration": ["check_cors"],  # handled differently
            "Host Header Injection": ["HostHeaderTest"],  # handled differently
            "Brute Force": ["?login=test"],  # فقط شناسایی endpoint
            "Open Redirect": ["?redirect=http://example.com", "?next=http://example.com"],
            "Clickjacking": ["Check X-Frame-Options"],
            "XMLRPC Exploit": ["/xmlrpc.php"],
            "Parameter Tampering": ["?id=9999", "?user_id=1"],
            "DOM XSS": ["document.write", "innerHTML", "eval("],
        }

    def load_urls(self):
        with open(self.urls_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def scan_url(self, url):
        print(f"[Scanning] {url}")
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 200:
                print(f"   [SKIP] {url} returned status {r.status_code}")
                return

            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")

            # 1. OTP Bypass & Brute Force
            if "otp" in url.lower():
                self.vulnerabilities.append({"url": url, "type": "OTP Bypass", "payload": "Detected OTP endpoint"})
                print(f"   [VULN] OTP Bypass -> {url}")
            if any(x in url.lower() for x in ["login", "auth"]):
                self.vulnerabilities.append({"url": url, "type": "Brute Force", "payload": "Login endpoint detected"})
                print(f"   [VULN] Brute Force -> {url}")

            # 2. Privilege Escalation
            if any(x in url.lower() for x in ["admin", "role", "dashboard"]):
                self.vulnerabilities.append({"url": url, "type": "Privilege Escalation", "payload": "Admin/role endpoint"})
                print(f"   [VULN] Privilege Escalation -> {url}")

            # 3. CORS Misconfiguration
            try:
                cors_resp = requests.get(url, headers={"Origin": "http://evil.com"}, timeout=5)
                acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*" or "evil.com" in acao:
                    self.vulnerabilities.append({"url": url, "type": "CORS Misconfiguration", "payload": f"Allowed Origin: {acao}"})
                    print(f"   [VULN] CORS Misconfiguration -> {url}")
            except:
                pass

            # 4. Host Header Injection
            try:
                host_resp = requests.get(url, headers={"Host": "evil.com"}, timeout=5)
                if "evil.com" in host_resp.text[:500]:
                    self.vulnerabilities.append({"url": url, "type": "Host Header Injection", "payload": "Reflected Host"})
                    print(f"   [VULN] Host Header Injection -> {url}")
            except:
                pass

            # 5. Open Redirect
            for payload in ["?redirect=http://example.com", "?next=http://example.com"]:
                test_url = url + payload if "?" in url else url + "?" + payload[1:]
                try:
                    resp = requests.get(test_url, allow_redirects=False, timeout=5)
                    location = resp.headers.get("Location", "")
                    if "example.com" in location:
                        self.vulnerabilities.append({"url": url, "type": "Open Redirect", "payload": payload})
                        print(f"   [VULN] Open Redirect -> {url}")
                except:
                    pass

            # 6. Clickjacking
            if "X-Frame-Options" not in r.headers:
                self.vulnerabilities.append({"url": url, "type": "Clickjacking", "payload": "Missing X-Frame-Options"})
                print(f"   [VULN] Clickjacking -> {url}")

            # 7. XMLRPC Exploit
            if "/xmlrpc.php" in url:
                self.vulnerabilities.append({"url": url, "type": "XMLRPC Exploit", "payload": "XMLRPC endpoint"})
                print(f"   [VULN] XMLRPC Exploit -> {url}")

            # 8. Parameter Tampering
            if "id=" in url or "user_id=" in url:
                test_url = re.sub(r"(id|user_id)=\d+", r"\1=9999", url)
                self.vulnerabilities.append({"url": url, "type": "Parameter Tampering", "payload": test_url})
                print(f"   [VULN] Parameter Tampering -> {url}")

            # 9. DOM XSS / Injection
            if re.search(r"(document\.write|innerHTML|eval\()", r.text):
                self.vulnerabilities.append({"url": url, "type": "DOM XSS / Injection", "payload": "Potential JS sink"})
                print(f"   [VULN] DOM XSS / Injection -> {url}")

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
            f.write("<html><head><title>P2 Scan Report</title></head><body>")
            f.write("<h1>P2 Security Scan Report</h1>")
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
        print("Usage: python scanner_p2.py urls.txt")
        sys.exit(1)

    scanner = P2VulnerabilityScanner(sys.argv[1])
    scanner.run()
