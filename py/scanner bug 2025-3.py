import requests
import re
import csv
import json
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import concurrent.futures
import os
from typing import List, Dict, Set

class SecurityScanner:
    def __init__(self, target_url, output_prefix="scan_result"):
        self.target_url = target_url.rstrip('/')
        self.output_prefix = output_prefix
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.found_issues = []
        
        # کلیدواژه‌ها برای جستجو
        self.keywords = [
            'main', 'app', 'runtime', 'bundle', 'polyfills', 'auth', 
            'config', 'settings', 'local', 'dev', 'data', 'api', 
            'session', 'user', 'core', 'client', 'server', 'utils', 'base'
        ]
        
        # پسوندهای فایل‌های حساس
        self.sensitive_extensions = [
            '.env', '.config', '.json', '.xml', '.yml', '.yaml', 
            '.php', '.asp', '.aspx', '.jsp', '.sql', '.txt', '.log'
        ]
        
        # endpointهای حساس
        self.sensitive_endpoints = [
            'admin', 'login', 'api', 'config', 'debug', 'test',
            'upload', 'file', 'console', 'adminer', 'phpmyadmin'
        ]

    def check_url(self, url):
        """بررسی یک URL برای یافتن محتوای حساس"""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                content = response.text.lower()
                
                # بررسی انواع آسیب‌پذیری‌ها
                issues = self.analyze_content(url, content, response)
                
                if issues:
                    self.found_issues.extend(issues)
                    
        except requests.RequestException:
            pass

    def analyze_content(self, url, content, response):
        """آنالیز محتوا برای یافتن آسیب‌پذیری‌ها"""
        issues = []
        
        # 1. اطلاعات حساس
        sensitive_patterns = {
            'password': r'password\s*[=:]\s*[\'"]?([^\'"\s]+)',
            'api_key': r'api[_-]?key\s*[=:]\s*[\'"]?([^\'"\s]+)',
            'jwt_secret': r'jwt[_-]?secret\s*[=:]\s*[\'"]?([^\'"\s]+)',
            'database_url': r'database[_-]?url\s*[=:]\s*[\'"]?([^\'"\s]+)',
            'aws_key': r'aws[_-]?access[_-]?key\s*[=:]\s*[\'"]?([^\'"\s]+)',
            'private_key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'
        }
        
        for issue_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    issues.append({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'severity': 'High',
                        'description': f'{issue_type} found: {match[:50]}...',
                        'details': f'Found {issue_type} in response content'
                    })
        
        # 2. فایل‌های پیکربندی
        if any(ext in url for ext in self.sensitive_extensions):
            issues.append({
                'type': 'Config File Disclosure',
                'url': url,
                'severity': 'Medium',
                'description': f'Sensitive configuration file exposed: {url}',
                'details': 'Configuration files should not be accessible via web'
            })
        
        # 3. صفحات لاگین پنهان
        login_indicators = ['login', 'signin', 'auth', 'authenticate', 'password']
        if any(indicator in url for indicator in login_indicators):
            issues.append({
                'type': 'Hidden Login Portal',
                'url': url,
                'severity': 'Low',
                'description': f'Potential login portal found: {url}',
                'details': 'This might be a hidden or administrative login portal'
            })
        
        # 4. endpointهای آپلود فایل
        upload_indicators = ['upload', 'file', 'attach', 'import']
        if any(indicator in url for indicator in upload_indicators):
            issues.append({
                'type': 'File Upload Endpoint',
                'url': url,
                'severity': 'Medium',
                'description': f'File upload functionality found: {url}',
                'details': 'File upload endpoints can be vulnerable if not properly secured'
            })
        
        # 5. پارامترهای redirect
        redirect_params = ['redirect', 'next', 'return', 'url']
        if any(param in content for param in redirect_params):
            issues.append({
                'type': 'Open Redirection',
                'url': url,
                'severity': 'Medium',
                'description': f'Potential open redirect parameter found in: {url}',
                'details': 'URL contains parameters that could be used for open redirect attacks'
            })
        
        return issues

    def crawl_page(self, url, visited_urls):
        """کراول کردن صفحه برای یافتن لینک‌های بیشتر"""
        if url in visited_urls:
            return []
        
        visited_urls.add(url)
        found_urls = set()
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # استخراج تمام لینک‌ها
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    parsed_url = urlparse(full_url)
                    
                    # فیلتر کردن لینک‌های خارج از دامنه هدف
                    if self.target_url in full_url and full_url not in visited_urls:
                        found_urls.add(full_url)
                        
                # استخراج اسکریپت‌ها و فایل‌های جاوااسکریپت
                for script in soup.find_all('script', src=True):
                    full_url = urljoin(url, script['src'])
                    if self.target_url in full_url and full_url not in visited_urls:
                        found_urls.add(full_url)
                        
        except requests.RequestException:
            pass
            
        return list(found_urls)

    def generate_urls_to_scan(self):
        """تولید لیست URLهای احتمالی برای اسکن"""
        urls_to_scan = set()
        
        # URLهای اصلی
        urls_to_scan.add(self.target_url)
        
        # URLهای با کلیدواژه‌ها
        for keyword in self.keywords:
            urls_to_scan.add(f"{self.target_url}/{keyword}")
            urls_to_scan.add(f"{self.target_url}/{keyword}.js")
            urls_to_scan.add(f"{self.target_url}/{keyword}.json")
        
        # URLهای با endpointهای حساس
        for endpoint in self.sensitive_endpoints:
            urls_to_scan.add(f"{self.target_url}/{endpoint}")
            urls_to_scan.add(f"{self.target_url}/{endpoint}/")
        
        # URLهای با پسوندهای حساس
        for ext in self.sensitive_extensions:
            urls_to_scan.add(f"{self.target_url}/config{ext}")
            urls_to_scan.add(f"{self.target_url}/settings{ext}")
            urls_to_scan.add(f"{self.target_url}/production{ext}")
            urls_to_scan.add(f"{self.target_url}/development{ext}")
        
        return list(urls_to_scan)

    def scan(self):
        """اجرای اسکن کامل"""
        print(f"[*] Starting scan of {self.target_url}")
        
        # تولید URLهای اولیه برای اسکن
        urls_to_scan = self.generate_urls_to_scan()
        
        # کراول کردن اولیه برای یافتن URLهای بیشتر
        print("[*] Crawling to find additional URLs...")
        visited_urls = set()
        to_visit = [self.target_url]
        
        while to_visit and len(visited_urls) < 100:  # محدودیت برای جلوگیری از کراول بی‌پایان
            current_url = to_visit.pop(0)
            new_urls = self.crawl_page(current_url, visited_urls)
            to_visit.extend(new_urls)
            urls_to_scan.extend(new_urls)
        
        # حذف duplicateها
        urls_to_scan = list(set(urls_to_scan))
        print(f"[*] Found {len(urls_to_scan)} URLs to scan")
        
        # اسکن همزمان URLها
        print("[*] Scanning URLs for vulnerabilities...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_url, urls_to_scan)
        
        # ذخیره نتایج
        self.save_results()
        
        print(f"[*] Scan completed. Found {len(self.found_issues)} potential issues")

    def save_results(self):
        """ذخیره نتایج در فایل‌های CSV و HTML"""
        if not self.found_issues:
            print("[!] No issues found to report")
            return
        
        # مرتب‌سازی بر اساس severity
        severity_order = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4}
        self.found_issues.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        # ذخیره در CSV
        csv_filename = f"{self.output_prefix}.csv"
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['type', 'severity', 'url', 'description', 'details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for issue in self.found_issues:
                writer.writerow(issue)
        
        # ذخیره در HTML
        html_filename = f"{self.output_prefix}.html"
        with open(html_filename, 'w', encoding='utf-8') as htmlfile:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Scan Report - {self.target_url}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr.critical {{ background-color: #ffcccc; }}
                    tr.high {{ background-color: #ffe6cc; }}
                    tr.medium {{ background-color: #ffffcc; }}
                    tr.low {{ background-color: #e6ffcc; }}
                </style>
            </head>
            <body>
                <h1>Security Scan Report</h1>
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Total Issues Found:</strong> {len(self.found_issues)}</p>
                
                <h2>Vulnerabilities</h2>
                <table>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>URL</th>
                        <th>Description</th>
                    </tr>
            """
            
            for issue in self.found_issues:
                html_content += f"""
                    <tr class="{issue['severity'].lower()}">
                        <td>{issue['type']}</td>
                        <td>{issue['severity']}</td>
                        <td><a href="{issue['url']}" target="_blank">{issue['url']}</a></td>
                        <td>{issue['description']}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            </body>
            </html>
            """
            
            htmlfile.write(html_content)
        
        print(f"[*] Results saved to {csv_filename} and {html_filename}")

def main():
    parser = argparse.ArgumentParser(description='Security Scanner for Web Applications')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', default='scan_result', help='Output file prefix')
    
    args = parser.parse_args()
    
    # غیرفعال کردن هشدارهای SSL
    requests.packages.urllib3.disable_warnings()
    
    scanner = SecurityScanner(args.target, args.output)
    scanner.scan()

if __name__ == '__main__':
    main()
