import requests
from bs4 import BeautifulSoup
import re
import sys
import csv

class P2CustomScanner:
    def __init__(self, urls_file):
        self.urls_file = urls_file
        self.vulnerabilities = []

    def load_urls(self):
        with open(self.urls_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def log_vuln(self, url, vuln_type, details=""):
        self.vulnerabilities.append({"url": url, "type": vuln_type, "details": details})
        print(f"[VULN] {vuln_type} -> {url} ({details})")

    # --------------------
    # P2 Checks
    # --------------------
    def check_improper_access_control(self, url):
        # شناسایی endpointهای حساس admin/user
        if any(x in url.lower() for x in ["/admin", "/dashboard", "/settings"]):
            self.log_vuln(url, "Improper Access Control", "Potential access control issue")

    def check_account_verification_bypass(self, url):
        if "verify" in url.lower() or "activate" in url.lower():
            self.log_vuln(url, "Account Verification Bypass", "Verification endpoint detected")

    def check_admin_panel_bypass(self, url):
        if "/admin" in url.lower():
            self.log_vuln(url, "Admin Panel Bypass", "Admin panel endpoint detected")

    def check_invite_link_reset_password(self, url):
        if "invite" in url.lower() and "reset" in url.lower():
            self.log_vuln(url, "Invite Link Reset Password Abuse", "Invite+Reset endpoint detected")

    def check_password_bypass_response(self, url):
        if any(x in url.lower() for x in ["login", "auth"]):
            self.log_vuln(url, "Password Bypass Response Manipulation", "Check login response handling")

    def check_otp_bypass(self, url):
        if "otp" in url.lower():
            self.log_vuln(url, "OTP Bypass", "OTP endpoint detected (logic/code check)")

    # Medium Impact / P2
    def check_user_info_leak(self, url):
        try:
            r = requests.get(url, timeout=5)
            if re.search(r"(email|username|full_name|phone|address)", r.text, re.I):
                self.log_vuln(url, "User Information Leak", "Sensitive info pattern detected")
        except:
            pass

    def check_misconfiguration(self, url):
        try:
            r = requests.get(url, timeout=5)
            if "Server:" in r.headers or "X-Powered-By" in r.headers:
                self.log_vuln(url, "Misconfiguration", "Server info leaked in headers")
        except:
            pass

    def check_multi_vulnerability(self, url):
        # اگر چند vuln در متن یافت شد
        try:
            r = requests.get(url, timeout=5)
            count = 0
            patterns = [r"(email|username)", r"(Server:)", r"(otp)"]
            for p in patterns:
                if re.search(p, r.text, re.I):
                    count += 1
            if count >= 2:
                self.log_vuln(url, "Multi Vulnerability", f"{count} patterns detected")
        except:
            pass

    def check_admin_email_enum(self, url):
        if re.search(r"admin@|support@|webmaster@", url, re.I):
            self.log_vuln(url, "Admin Email Enumeration", "Possible admin email in URL")

    # --------------------
    # Main scan
    # --------------------
    def scan_url(self, url):
        print(f"[Scanning] {url}")
        self.check_improper_access_control(url)
        self.check_account_verification_bypass(url)
        self.check_admin_panel_bypass(url)
        self.check_invite_link_reset_password(url)
        self.check_password_bypass_response(url)
        self.check_otp_bypass(url)
        self.check_user_info_leak(url)
        self.check_misconfiguration(url)
        self.check_multi_vulnerability(url)
        self.check_admin_email_enum(url)

    # --------------------
    # Save reports
    # --------------------
    def save_csv(self):
        with open("report.csv", "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["type", "url", "details"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vuln in self.vulnerabilities:
                writer.writerow(vuln)

    def save_html(self):
        with open("report.html", "w", encoding="utf-8") as f:
            f.write("<html><head><title>P2 Custom Scan Report</title></head><body>")
            f.write("<h1>P2 Custom Security Scan Report</h1>")
            f.write("<table border='1' style='border-collapse:collapse;width:100%'>")
            f.write("<tr><th>Type</th><th>URL</th><th>Details</th></tr>")
            for vuln in self.vulnerabilities:
                f.write(f"<tr><td>{vuln['type']}</td><td>{vuln['url']}</td><td>{vuln['details']}</td></tr>")
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
        print("Usage: python scanner_p2_custom.py urls.txt")
        sys.exit(1)

    scanner = P2CustomScanner(sys.argv[1])
    scanner.run()
