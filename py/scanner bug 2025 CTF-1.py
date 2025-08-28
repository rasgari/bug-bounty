#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import aiohttp
import asyncio
import async_timeout
import sqlite3
import csv
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
import re
import os
import sys
from typing import List, Dict, Set, Optional
import json

class AdvancedCrawlerScanner:
    def __init__(self, target_url, profile="bounty", output_prefix="scan_result", max_concurrency=20, crawl_depth=2):
        self.target_url = target_url.rstrip('/')
        self.profile = profile
        self.output_prefix = output_prefix
        self.max_concurrency = max_concurrency
        self.crawl_depth = crawl_depth
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.found_issues = []
        self.db_conn = None
        
        # پیکربندی بر اساس پروفایل
        self.setup_profile_config()
        
        # ایجاد دیتابیس
        self.setup_database()

    def setup_profile_config(self):
        """تنظیمات پیکربندی بر اساس پروفایل انتخاب شده"""
        if self.profile == "ctf":
            # پیکربندی مخصوص CTF
            self.keywords = [
                'flag', 'admin', 'login', 'config', 'backup', 'secret',
                'debug', 'test', 'console', 'upload', 'shell', 'cmd',
                'root', 'password', 'token', 'key', 'auth', 'api'
            ]
            
            self.sensitive_extensions = [
                '.txt', '.bak', '.old', '.swp', '.save', '.backup',
                '.sql', '.db', '.env', '.config', '.json', '.xml',
                '.yml', '.yaml', '.php', '.asp', '.aspx', '.jsp'
            ]
            
            self.sensitive_endpoints = [
                'flag', 'admin', 'login', 'config', 'backup', 'secret',
                'debug', 'test', 'console', 'upload', 'shell', 'cmd',
                'cgi-bin', 'phpmyadmin', 'adminer', 'wp-admin', 'administrator'
            ]
            
        else:  # پروفایل پیشفرض: bounty
            # پیکربندی مخصوص Bug Bounty
            self.keywords = [
                'api', 'v1', 'v2', 'graphql', 'rest', 'soap', 'admin',
                'login', 'auth', 'oauth', 'token', 'jwt', 'session',
                'user', 'account', 'profile', 'config', 'setting',
                'upload', 'file', 'import', 'export', 'backup', 'db',
                'database', 'password', 'reset', 'forgot', 'register'
            ]
            
            self.sensitive_extensions = [
                '.env', '.config', '.json', '.xml', '.yml', '.yaml',
                '.php', '.asp', '.aspx', '.jsp', '.sql', '.txt', '.log',
                '.bak', '.backup', '.swp', '.git', '.svn', '.DS_Store'
            ]
            
            self.sensitive_endpoints = [
                'admin', 'login', 'api', 'config', 'debug', 'test',
                'upload', 'file', 'console', 'adminer', 'phpmyadmin',
                'wp-admin', 'administrator', 'phpinfo', 'env', 'configs',
                'backup', 'backups', 'database', 'db', '.git', 'README'
            ]
        
        # الگوهای اطلاعات حساس
        self.sensitive_patterns = {
            'password': r'password\s*[=:]\s*[\'"]?([^\'"\s]{4,})',
            'api_key': r'api[_-]?key\s*[=:]\s*[\'"]?([^\'"\s]{8,})',
            'jwt_secret': r'jwt[_-]?secret\s*[=:]\s*[\'"]?([^\'"\s]{10,})',
            'database_url': r'(mysql|postgresql|mongodb)://([^:]+):([^@]+)@',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            'auth_token': r'eyJhbGciOiJ[^\s"]{20,}',
            'firebase_url': r'https://[a-zA-Z0-9.-]+\.firebaseio\.com',
        }

    def setup_database(self):
        """ایجاد و راه‌اندازی دیتابیس SQLite"""
        db_name = f"{self.output_prefix}.db"
        self.db_conn = sqlite3.connect(db_name)
        cursor = self.db_conn.cursor()
        
        # ایجاد جدول برای URLهای کراول شده
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawled_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                content_type TEXT,
                title TEXT,
                crawled_at DATETIME
            )
        ''')
        
        # ایجاد جدول برای یافته‌های امنیتی
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                severity TEXT,
                url TEXT,
                description TEXT,
                details TEXT,
                found_at DATETIME
            )
        ''')
        
        self.db_conn.commit()
        print(f"[*] Database created: {db_name}")

    async def fetch_url(self, session, url):
        """دریافت یک URL به صورت ناهمزمان"""
        try:
            async with async_timeout.timeout(10):
                async with session.get(url, ssl=False, allow_redirects=True) as response:
                    content = await response.text()
                    status = response.status
                    content_type = response.headers.get('content-type', '')
                    
                    # ذخیره در دیتابیس
                    await self.store_crawled_url(url, status, content_type, content)
                    
                    return url, content, status, content_type
        except Exception as e:
            print(f"[-] Error fetching {url}: {str(e)}")
            return url, None, 0, ""

    async def store_crawled_url(self, url, status_code, content_type, content):
        """ذخیره URL کراول شده در دیتابیس"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            title = soup.title.string if soup.title else "No title"
            
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO crawled_urls 
                (url, status_code, content_type, title, crawled_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, status_code, content_type, title, datetime.now()))
            
            self.db_conn.commit()
        except Exception as e:
            print(f"[-] Error storing URL {url}: {str(e)}")

    async def store_security_finding(self, finding):
        """ذخیره یافته امنیتی در دیتابیس"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO security_findings 
                (type, severity, url, description, details, found_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                finding['type'], 
                finding['severity'], 
                finding['url'], 
                finding['description'], 
                finding['details'], 
                datetime.now()
            ))
            
            self.db_conn.commit()
            self.found_issues.append(finding)
        except Exception as e:
            print(f"[-] Error storing finding: {str(e)}")

    async def analyze_content(self, url, content, response_headers):
        """آنالیز محتوا برای یافتن آسیب‌پذیری‌ها"""
        findings = []
        
        if not content:
            return findings
        
        content_lower = content.lower()
        
        # 1. اطلاعات حساس
        for issue_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        match = ' '.join(match)
                    finding = {
                        'type': 'Sensitive Information Exposure',
                        'severity': 'High',
                        'url': url,
                        'description': f'{issue_type} found: {match[:50]}...',
                        'details': f'Found {issue_type} in response content'
                    }
                    findings.append(finding)
                    await self.store_security_finding(finding)
        
        # 2. فایل‌های پیکربندی
        if any(ext in url.lower() for ext in self.sensitive_extensions):
            finding = {
                'type': 'Config File Disclosure',
                'severity': 'Medium',
                'url': url,
                'description': f'Sensitive configuration file exposed: {url}',
                'details': 'Configuration files should not be accessible via web'
            }
            findings.append(finding)
            await self.store_security_finding(finding)
        
        # 3. صفحات لاگین پنهان
        login_indicators = ['login', 'signin', 'auth', 'authenticate', 'password', 'admin']
        if (any(indicator in url.lower() for indicator in login_indicators) and 
            any(tag in content_lower for tag in ['<form', 'type="password"'])):
            finding = {
                'type': 'Hidden Login Portal',
                'severity': 'Low',
                'url': url,
                'description': f'Potential login portal found: {url}',
                'details': 'This might be a hidden or administrative login portal'
            }
            findings.append(finding)
            await self.store_security_finding(finding)
        
        # 4. آسیب‌پذیری‌های تزریق
        injection_patterns = {
            'SQL Injection': [r"sql syntax", r"mysql_fetch", r"ORA-01756", r"unclosed quotation mark"],
            'XSS': [r"alert\(", r"onerror=", r"<script>", r"javascript:"],
            'LFI': [r"etc/passwd", r"boot.ini", r"win.ini", r"proc/self/environ"],
            'Command Injection': [r"sh: ", r"bash: ", r"cmd.exe", r"command not found"]
        }
        
        for vuln_type, patterns in injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    finding = {
                        'type': f'{vuln_type}',
                        'severity': 'High' if vuln_type in ['SQL Injection', 'Command Injection'] else 'Medium',
                        'url': url,
                        'description': f'Potential {vuln_type} vulnerability found',
                        'details': f'Response contains {vuln_type} signature: {pattern}'
                    }
                    findings.append(finding)
                    await self.store_security_finding(finding)
        
        return findings

    async def extract_links(self, url, content):
        """استخراج لینک‌ها از محتوای HTML"""
        if not content:
            return []
        
        soup = BeautifulSoup(content, 'html.parser')
        links = set()
        
        # استخراج لینک‌های <a>
        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if self.is_valid_url(full_url):
                links.add(full_url)
        
        # استخراج لینک‌های <script>
        for script in soup.find_all('script', src=True):
            full_url = urljoin(url, script['src'])
            if self.is_valid_url(full_url):
                links.add(full_url)
        
        # استخراج لینک‌های <form>
        for form in soup.find_all('form', action=True):
            full_url = urljoin(url, form['action'])
            if self.is_valid_url(full_url):
                links.add(full_url)
        
        return list(links)

    def is_valid_url(self, url):
        """بررسی معتبر بودن URL"""
        if not url.startswith(self.target_url):
            return False
        
        parsed = urlparse(url)
        if parsed.path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.css', '.ico')):
            return False
        
        return True

    def generate_target_urls(self):
        """تولید لیست URLهای هدف برای اسکن"""
        urls = set()
        
        # URL اصلی
        urls.add(self.target_url)
        
        # URLهای با کلیدواژه‌ها
        for keyword in self.keywords:
            urls.add(f"{self.target_url}/{keyword}")
            urls.add(f"{self.target_url}/{keyword}.php")
            urls.add(f"{self.target_url}/{keyword}.js")
            urls.add(f"{self.target_url}/{keyword}.json")
        
        # URLهای با endpointهای حساس
        for endpoint in self.sensitive_endpoints:
            urls.add(f"{self.target_url}/{endpoint}")
            urls.add(f"{self.target_url}/{endpoint}/")
            urls.add(f"{self.target_url}/{endpoint}.php")
        
        # URLهای با پسوندهای حساس
        for ext in self.sensitive_extensions:
            urls.add(f"{self.target_url}/config{ext}")
            urls.add(f"{self.target_url}/settings{ext}")
            urls.add(f"{self.target_url}/backup{ext}")
        
        return list(urls)

    async def crawl_and_scan(self):
        """اجرای کراول و اسکن ناهمزمان"""
        print(f"[*] Starting {self.profile} scan of {self.target_url}")
        
        # تولید URLهای اولیه
        initial_urls = self.generate_target_urls()
        self.urls_to_scan.update(initial_urls)
        
        # ایجاد session ناهمزمان
        connector = aiohttp.TCPConnector(limit=self.max_concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # کراول و اسکن در عمق‌های مختلف
            for depth in range(self.crawl_depth):
                print(f"[*] Crawling depth {depth + 1}, URLs: {len(self.urls_to_scan)}")
                
                # اسکن URLهای فعلی
                tasks = []
                for url in list(self.urls_to_scan):
                    if url not in self.visited_urls:
                        tasks.append(self.fetch_url(session, url))
                
                # اجرای تمام tasks به صورت ناهمزمان
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # پردازش نتایج
                new_urls = set()
                for result in results:
                    if isinstance(result, Exception):
                        continue
                    
                    url, content, status, content_type = result
                    self.visited_urls.add(url)
                    
                    if content and status == 200:
                        # آنالیز محتوا برای آسیب‌پذیری
                        await self.analyze_content(url, content, {})
                        
                        # استخراج لینک‌های جدید
                        if 'text/html' in content_type:
                            links = await self.extract_links(url, content)
                            new_urls.update(links)
                
                # اضافه کردن لینک‌های جدید برای اسکن در عمق بعدی
                self.urls_to_scan.update(new_urls)
        
        print(f"[*] Crawling completed. Found {len(self.visited_urls)} URLs")
        print(f"[*] Found {len(self.found_issues)} security issues")

    def export_results(self):
        """خروجی نتایج به فرمت‌های CSV و HTML"""
        # خروجی CSV
        csv_filename = f"{self.output_prefix}.csv"
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['type', 'severity', 'url', 'description', 'details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for issue in self.found_issues:
                writer.writerow(issue)
        
        # خروجی HTML
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
                <h1>Security Scan Report - {self.profile.upper()} Profile</h1>
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
        
        print(f"[*] Results exported to {csv_filename} and {html_filename}")

    async def run(self):
        """اجرای کامل اسکنر"""
        start_time = datetime.now()
        
        try:
            await self.crawl_and_scan()
            self.export_results()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            print(f"[*] Scan completed in {duration}")
            print(f"[*] Total URLs scanned: {len(self.visited_urls)}")
            print(f"[*] Total issues found: {len(self.found_issues)}")
            
        except Exception as e:
            print(f"[-] Error during scanning: {str(e)}")
        
        finally:
            if self.db_conn:
                self.db_conn.close()

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Crawler & Scanner for Bug Bounty and CTF')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-p', '--profile', choices=['bounty', 'ctf'], default='bounty', 
                       help='Scan profile: bounty (default) or ctf')
    parser.add_argument('-o', '--output', default='scan_result', help='Output file prefix')
    parser.add_argument('-c', '--concurrency', type=int, default=20, help='Number of concurrent requests')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    
    args = parser.parse_args()
    
    # ایجاد اسکنر و اجرا
    scanner = AdvancedCrawlerScanner(
        target_url=args.target,
        profile=args.profile,
        output_prefix=args.output,
        max_concurrency=args.concurrency,
        crawl_depth=args.depth
    )
    
    # اجرای اسکن
    asyncio.run(scanner.run())

if __name__ == '__main__':
    main()
