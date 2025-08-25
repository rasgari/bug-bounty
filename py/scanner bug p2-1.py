import requests
import sys
import re
from urllib.parse import urljoin, urlencode

class P2Scanner:
    def __init__(self, urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            self.urls = [u.strip() for u in f if u.strip()]
        self.vulns = []

    def log(self, url, vuln_type, details=""):
        finding = {"url": url, "vulnerability": vuln_type, "details": details}
        self.vulns.append(finding)
        print(f"[!] {url} -> {vuln_type} ({details})")

    # 1. OTP Bypass (پایه‌ای)
    def check_otp_bypass(self, url):
        if "otp" in url.lower():
            self.log(url, "OTP Bypass", "Possible OTP endpoint")

    # 2. Privilege Escalation
    def check_privilege_escalation(self, url):
        if any(x in url.lower() for x in ["admin", "role", "permission"]):
            self.log(url, "Privilege Escalation", "Suspicious admin/role endpoint")

    # 3. CORS Misconfiguration
    def check_cors(self, url):
        try:
            r = requests.get(url, headers={"Origin": "http://evil.com"}, timeout=5)
            if "Access-Control-Allow-Origin" in r.headers:
                if r.headers["Access-Control-Allow-Origin"] == "*" or "evil.com" in r.headers["Access-Control-Allow-Origin"]:
                    self.log(url, "CORS Misconfiguration", f"Allowed Origin: {r.headers['Access-Control-Allow-Origin']}")
        except:
            pass

    # 4. Host Header Injection
    def check_host_header(self, url):
        try:
            r = requests.get(url, headers={"Host": "evil.com"}, timeout=5)
            if "evil.com" in r.text:
                self.log(url, "Host Header Injection", "Reflected host in response")
        except:
            pass

    # 5. Brute Force (بدون Rate Limit)
    def check_bruteforce(self, url):
        if any(x in url.lower() for x in ["login", "auth"]):
            self.log(url, "Brute Force Possible", "No rate-limit detected (manual check needed)")

    # 6. Open Redirect
    def check_open_redirect(self, url):
        payloads = ["?redirect=http://evil.com", "?next=http://evil.com"]
        for p in payloads:
            test_url = url + p
            try:
                r = requests.get(test_url, allow_redirects=False, timeout=5)
                if "evil.com" in r.headers.get("Location", ""):
                    self.log(url, "Open Redirect", f"Payload: {p}")
            except:
                pass

    # 7. Clickjacking
    def check_clickjacking(self, url):
        try:
            r = requests.get(url, timeout=5)
            if "X-Frame-Options" not in r.headers:
                self.log(url, "Clickjacking", "Missing X-Frame-Options header")
        except:
            pass

    # 8. XMLRPC Exploit (WordPress)
    def check_xmlrpc(self, url):
        if "xmlrpc.php" in url:
            self.log(url, "XMLRPC Exploit", "WordPress xmlrpc endpoint exposed")

    # 9. Parameter Tampering
    def check_param_tampering(self, url):
        if "id=" in url.lower():
            test_url = re.sub(r"id=\d+", "id=9999", url)
            if test_url != url:
                self.log(url, "Parameter Tampering", f"Try: {test_url}")

    # 10. DOM XSS
    def check_dom_xss(self, url):
        try:
            r = requests.get(url, timeout=5)
            if re.search(r"(document\.write|innerHTML|eval\()", r.text):
                self.log(url, "DOM XSS", "Dangerous JS function found")
        except:
            pass

    def run(self):
        print(f"Starting P2 Security Scan on {len(self.urls)} URLs...")
        for url in self.urls:
            self.check_otp_bypass(url)
            self.check_privilege_escalation(url)
            self.check_cors(url)
            self.check_host_header(url)
            self.check_bruteforce(url)
            self.check_open_redirect(url)
            self.check_clickjacking(url)
            self.check_xmlrpc(url)
            self.check_param_tampering(url)
            self.check_dom_xss(url)

        print("\n=== Scan Complete ===")
        print(f"Total Findings: {len(self.vulns)}")
        for v in self.vulns:
            print(v)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py urls.txt")
        sys.exit(1)

    scanner = P2Scanner(sys.argv[1])
    scanner.run()
