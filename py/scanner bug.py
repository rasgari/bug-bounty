import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from concurrent.futures import ThreadPoolExecutor
import re
import csv
from urllib.parse import urljoin

class WebSecurityScanner:
    def __init__(self, urls_file):
        # خواندن URLها از فایل
        with open(urls_file, "r", encoding="utf-8") as f:
            self.urls = [line.strip() for line in f if line.strip()]
        self.visited_urls = set()
        self.vulnerabilities = []

        # تنظیمات Selenium Chrome Headless
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        self.driver = webdriver.Chrome(options=chrome_options)

    # استخراج لینک‌های داخلی با Selenium
    def crawl(self, url):
        try:
            self.driver.get(url)
            links = self.driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href and href not in self.visited_urls:
                    self.visited_urls.add(href)
        except:
            pass

    # بررسی SQL Injection
    def check_sql_injection(self, url):
        test_url = url + "'"
        try:
            r = requests.get(test_url, timeout=5)
            errors = ["you have an error in your sql syntax", "mysql", "syntax error", "unclosed quotation mark"]
            for error in errors:
                if error in r.text.lower():
                    self.report_vulnerability({"type": "SQL Injection", "url": url})
        except:
            pass

    # بررسی XSS
    def check_xss(self, url):
        payload = "<script>alert(1)</script>"
        test_url = url + ("&q=" if "?" in url else "?q=") + payload
        try:
            r = requests.get(test_url, timeout=5)
            if payload in r.text:
                self.report_vulnerability({"type": "XSS", "url": url})
        except:
            pass

    # بررسی اطلاعات حساس
    def check_sensitive_info(self, url):
        try:
            r = requests.get(url, timeout=5)
            if re.search(r"apikey|password|secret|token|aws_secret|private_key", r.text, re.I):
                self.report_vulnerability({"type": "Sensitive Info Disclosure", "url": url})
        except:
            pass

    # ذخیره آسیب‌پذیری پیدا شده
    def report_vulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)
        print("[VULNERABILITY FOUND]", vulnerability["type"], vulnerability["url"])

    # اسکن یک URL (crawl + تست‌ها)
    def scan_url(self, url):
        if url not in self.visited_urls:
            self.visited_urls.add(url)
            self.crawl(url)
        self.check_sql_injection(url)
        self.check_xss(url)
        self.check_sensitive_info(url)

    # اسکن تمام URLها
    def scan_all(self):
        print(f"Starting scan of {len(self.urls)} URLs from file")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.scan_url, self.urls)
        print(f"Scan complete. Total URLs visited: {len(self.visited_urls)}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        self.save_csv()
        self.save_html()
        self.driver.quit()

    # ذخیره CSV
    def save_csv(self, filename="vulnerabilities.csv"):
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["type", "url"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for v in self.vulnerabilities:
                writer.writerow(v)
        print(f"[CSV Saved] {filename}")

    # ذخیره HTML
    def save_html(self, filename="vulnerabilities.html"):
        html_content = "<html><head><title>Vulnerabilities Report</title></head><body>"
        html_content += "<h1>Vulnerabilities Report</h1>"
        html_content += "<table border='1' cellpadding='5' cellspacing='0'>"
        html_content += "<tr><th>Type</th><th>URL</th></tr>"
        for v in self.vulnerabilities:
            html_content += f"<tr><td>{v['type']}</td><td>{v['url']}</td></tr>"
        html_content += "</table></body></html>"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[HTML Saved] {filename}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <urls.txt>")
        sys.exit(1)

    urls_file = sys.argv[1]
    scanner = WebSecurityScanner(urls_file)
    scanner.scan_all()
