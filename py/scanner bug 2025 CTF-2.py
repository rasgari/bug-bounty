#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import aiohttp
import sqlite3
import csv
import json
import time
import re
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
import ssl
import warnings
warnings.filterwarnings("ignore")

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url, profile="bounty", threads=20, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.profile = profile.lower()
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.scanned_urls = set()
        
        # تنظیمات پروفایل
        self.setup_profile()
        
        # تنظیمات SSL
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # راه‌اندازی پایگاه داده
        self.setup_database()

    def setup_profile(self):
        """تنظیم پروفایل‌های مختلف"""
        if self.profile == "ctf":
            self.keywords = [
                'flag', 'admin', 'secret', 'hidden', 'debug', 'test', 'dev',
                'config', 'backup', 'temp', 'old', 'bak', 'tmp', 'log'
            ]
            self.suspicious_paths = [
                '/flag.txt', '/admin', '/secret', '/hidden', '/debug',
                '/config.php', '/backup', '/.git', '/.svn', '/robots.txt',
                '/sitemap.xml', '/.htaccess', '/web.config', '/flag',
                '/key.txt', '/password.txt', '/users.txt', '/admin.php'
            ]
            self.vulnerability_patterns = {
                'flag_disclosure': [
                    r'flag\{[^}]+\}',
                    r'CTF\{[^}]+\}',
                    r'FLAG\{[^}]+\}',
                    r'[a-f0-9]{32}',  # MD5 hash
                    r'[a-f0-9]{40}',  # SHA1 hash
                ],
                'sensitive_files': [
                    r'\.git', r'\.svn', r'\.env', r'config\.php',
                    r'backup\.', r'\.bak', r'\.old', r'\.tmp'
                ]
            }
        else:  # Bug Bounty profile
            self.keywords = [
                'main', 'app', 'runtime', 'bundle', 'polyfills', 'auth', 'config',
                'settings', 'local', 'dev', 'data', 'api', 'session', 'user',
                'core', 'client', 'server', 'utils', 'base', 'admin', 'login'
            ]
            self.suspicious_paths = [
                '/admin', '/login', '/auth', '/api', '/config', '/settings',
                '/dev', '/test', '/debug', '/backup', '/.env', '/config.json',
                '/web.config', '/app.config', '/settings.py', '/local.py',
                '/main.js', '/app.js', '/bundle.js', '/runtime.js',
                '/api/v1', '/api/v2', '/graphql', '/swagger', '/docs'
            ]
            self.vulnerability_patterns = {
                'hardcoded_credentials': [
                    r'password\s*[=:]\s*["\']([^"\']+)["\']',
                    r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
                    r'secret\s*[=:]\s*["\']([^"\']+)["\']',
                    r'token\s*[=:]\s*["\']([^"\']+)["\']'
                ],
                'jwt_secrets': [
                    r'jwt[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']',
                    r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
                ],
                'xss_vectors': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'eval\s*\(',
                    r'innerHTML\s*='
                ],
                'sql_injection': [
                    r'union\s+select',
                    r'order\s+by\s+\d+',
                    r'\'.*or.*\'.*=.*\'',
                    r'sleep\(\d+\)',
                    r'benchmark\('
                ]
            }

    def setup_database(self):
        """راه‌اندازی پایگاه داده SQLite"""
        self.db_name = f"scan_results_{int(time.time())}.db"
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        cursor = self.conn.cursor()
        
        # جدول URL های کرال شده
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawled_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                response_time REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # جدول آسیب‌پذیری‌ها
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                description TEXT,
                payload TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()

    async def create_session(self):
        """ایجاد session برای aiohttp"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ssl=self.ssl_context
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )

    async def fetch_url(self, session, url):
        """دریافت محتوای یک URL"""
        try:
            start_time = time.time()
            async with session.get(url) as response:
                content = await response.text()
                response_time = time.time() - start_time
                
                # ذخیره در پایگاه داده
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO crawled_urls 
                    (url, status_code, content_type, content_length, response_time)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    url, 
                    response.status,
                    response.headers.get('content-type', ''),
                    len(content),
                    response_time
                ))
                self.conn.commit()
                
                return {
                    'url': url,
                    'status': response.status,
                    'headers': dict(response.headers),
                    'content': content,
                    'response_time': response_time
                }
        except Exception as e:
            print(f"[-] خطا در دریافت {url}: {e}")
            return None

    async def crawl_website(self, session):
        """کرال کردن وب‌سایت"""
        print(f"[+] شروع کرال {self.target_url}")
        
        # دریافت صفحه اصلی
        main_page = await self.fetch_url(session, self.target_url)
        if not main_page:
            return
        
        soup = BeautifulSoup(main_page['content'], 'html.parser')
        
        # استخراج لینک‌ها
        links = set()
        for tag in soup.find_all(['a', 'script', 'link', 'img', 'form']):
            href = tag.get('href') or tag.get('src') or tag.get('action')
            if href:
                full_url = urljoin(self.target_url, href)
                if self.domain in full_url:
                    links.add(full_url)
        
        # کرال لینک‌های یافت شده
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for link in links:
            if link not in self.crawled_urls:
                self.crawled_urls.add(link)
                task = self.crawl_single_url(session, semaphore, link)
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def crawl_single_url(self, session, semaphore, url):
        """کرال یک URL مشخص"""
        async with semaphore:
            result = await self.fetch_url(session, url)
            if result and result['status'] == 200:
                await self.analyze_response(result)

    async def scan_suspicious_paths(self, session):
        """اسکن مسیرهای مشکوک"""
        print(f"[+] اسکن مسیرهای مشکوک")
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        # اسکن مسیرهای از پیش تعریف شده
        for path in self.suspicious_paths:
            url = urljoin(self.target_url, path)
            if url not in self.scanned_urls:
                self.scanned_urls.add(url)
                task = self.scan_single_url(session, semaphore, url)
                tasks.append(task)
        
        # اسکن بر اساس کلیدواژه‌ها
        extensions = ['.js', '.json', '.xml', '.txt', '.php', '.asp', '.jsp']
        for keyword in self.keywords:
            for ext in extensions:
                url = urljoin(self.target_url, f'/{keyword}{ext}')
                if url not in self.scanned_urls:
                    self.scanned_urls.add(url)
                    task = self.scan_single_url(session, semaphore, url)
                    tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def scan_single_url(self, session, semaphore, url):
        """اسکن یک URL مشخص"""
        async with semaphore:
            result = await self.fetch_url(session, url)
            if result:
                await self.analyze_response(result)

    async def analyze_response(self, response_data):
        """تجزیه و تحلیل پاسخ دریافتی"""
        url = response_data['url']
        content = response_data['content']
        headers = response_data['headers']
        status = response_data['status']
        
        # بررسی وضعیت پاسخ
        if status in [403][401]:
            await self.add_vulnerability(
                url, "Access Control", 
                f"Protected resource: HTTP {status}", 
                "Medium"
            )
        
        # بررسی هدرهای امنیتی
        await self.check_security_headers(url, headers)
        
        # بررسی الگوهای آسیب‌پذیری
        await self.check_vulnerability_patterns(url, content)
        
        # بررسی فایل‌های JavaScript
        if url.endswith('.js') or 'javascript' in headers.get('content-type', ''):
            await self.analyze_javascript(url, content)

    async def check_security_headers(self, url, headers):
        """بررسی هدرهای امنیتی"""
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection disabled',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                await self.add_vulnerability(
                    url, "Security Headers", description, "Low"
                )

    async def check_vulnerability_patterns(self, url, content):
        """بررسی الگوهای آسیب‌پذیری"""
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    severity = self.get_severity(vuln_type)
                    description = f"Found {len(matches)} matches for {vuln_type}"
                    
                    # اگر flag پیدا شد، آن را نمایش بده
                    if 'flag' in vuln_type.lower() and matches:
                        description += f" - Potential flags: {matches[:3]}"
                    
                    await self.add_vulnerability(
                        url, vuln_type.replace('_', ' ').title(),
                        description, severity, str(matches[:3])
                    )

    async def analyze_javascript(self, url, content):
        """تجزیه و تحلیل فایل‌های JavaScript"""
        js_patterns = {
            'api_endpoints': r'(?i)(https?://[^\s"\']+/api/[^\s"\']*)',
            'sensitive_data': r'(?i)(password|secret|key|token)\s*[=:]\s*["\']([^"\']{5,})["\']',
            'debug_info': r'(?i)(console\.log|debugger|alert)\s*\(',
            'ajax_calls': r'(?i)\$\.ajax\s*\(|\$\.get\s*\(|\$\.post\s*\(',
        }
        
        for pattern_type, pattern in js_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                severity = "High" if "sensitive" in pattern_type else "Medium"
                await self.add_vulnerability(
                    url, f"JavaScript {pattern_type.replace('_', ' ').title()}",
                    f"Found {len(matches)} {pattern_type} in JavaScript",
                    severity, str(matches[:3])
                )

    def get_severity(self, vuln_type):
        """تعیین شدت آسیب‌پذیری"""
        high_severity = ['hardcoded_credentials', 'jwt_secrets', 'flag_disclosure', 'sql_injection']
        medium_severity = ['xss_vectors', 'sensitive_files', 'api_endpoints']
        
        if vuln_type in high_severity:
            return "High"
        elif vuln_type in medium_severity:
            return "Medium"
        else:
            return "Low"

    async def add_vulnerability(self, url, vuln_type, description, severity, payload=""):
        """اضافه کردن آسیب‌پذیری"""
        vulnerability = {
            'url': url,
            'type': vuln_type,
            'description': description,
            'severity': severity,
            'payload': payload,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # ذخیره در پایگاه داده
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (url, vulnerability_type, severity, description, payload)
            VALUES (?, ?, ?, ?, ?)
        ''', (url, vuln_type, severity, description, payload))
        self.conn.commit()
        
        print(f"[{severity}] {vuln_type}: {url}")

    def generate_csv_report(self, filename=None):
        """تولید گزارش CSV"""
        if not filename:
            filename = f'{self.profile}_scan_report_{int(time.time())}.csv'
        
        # مرتب‌سازی بر اساس اهمیت
        severity_order = {'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(self.vulnerabilities, 
                            key=lambda x: severity_order.get(x['severity'], 4))
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'severity', 'type', 'url', 'description', 'payload']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in sorted_vulns:
                writer.writerow(vuln)
        
        print(f"[+] گزارش CSV ذخیره شد: {filename}")
        return filename

    def generate_html_report(self, filename=None):
        """تولید گزارش HTML"""
        if not filename:
            filename = f'{self.profile}_scan_report_{int(time.time())}.html'
        
        # مرتب‌سازی بر اساس اهمیت
        severity_order = {'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(self.vulnerabilities, 
                            key=lambda x: severity_order.get(x['severity'], 4))
        
        # آمار
        high_count = len([v for v in sorted_vulns if v['severity'] == 'High'])
        medium_count = len([v for v in sorted_vulns if v['severity'] == 'Medium'])
        low_count = len([v for v in sorted_vulns if v['severity'] == 'Low'])
        
        html_content = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="fa">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>گزارش اسکن {self.profile.upper()} - {self.domain}</title>
            <style>
                body {{ font-family: 'Tahoma', Arial, sans-serif; margin: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: rgba(255,255,255,0.95); color: #333; padding: 30px; border-radius: 15px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }}
                .profile-badge {{ display: inline-block; background: #e74c3c; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; margin-left: 10px; }}
                .summary {{ background: rgba(255,255,255,0.95); padding: 20px; border-radius: 15px; margin-bottom: 20px; box-shadow: 0 5px 15px rgba(0,0,0,0.2); }}
                .vulnerability {{ background: rgba(255,255,255,0.95); margin: 15px 0; padding: 20px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.2); }}
                .high {{ border-left: 6px solid #e74c3c; }}
                .medium {{ border-left: 6px solid #f39c12; }}
                .low {{ border-left: 6px solid #27ae60; }}
                .severity {{ font-weight: bold; padding: 8px 15px; border-radius: 20px; color: white; display: inline-block; }}
                .severity.high {{ background: linear-gradient(45deg, #e74c3c, #c0392b); }}
                .severity.medium {{ background: linear-gradient(45deg, #f39c12, #e67e22); }}
                .severity.low {{ background: linear-gradient(45deg, #27ae60, #229954); }}
                .url {{ color: #3498db; word-break: break-all; background: #f8f9fa; padding: 5px 10px; border-radius: 5px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
                .stat {{ background: linear-gradient(45deg, #3498db, #2980b9); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
                .payload {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 5px; font-family: monospace; margin-top: 10px; }}
                .filter-buttons {{ margin: 20px 0; }}
                .filter-btn {{ background: #34495e; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer; }}
                .filter-btn.active {{ background: #e74c3c; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 گزارش اسکن آسیب‌پذیری <span class="profile-badge">{self.profile.upper()}</span></h1>
                    <p><strong>هدف:</strong> {self.target_url}</p>
                    <p><strong>تاریخ اسکن:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>تعداد URL های کرال شده:</strong> {len(self.crawled_urls)}</p>
                </div>
                
                <div class="summary">
                    <h2>📊 خلاصه نتایج</h2>
                    <div class="stats">
                        <div class="stat">
                            <h3>{high_count}</h3>
                            <p>آسیب‌پذیری بحرانی</p>
                        </div>
                        <div class="stat">
                            <h3>{medium_count}</h3>
                            <p>آسیب‌پذیری متوسط</p>
                        </div>
                        <div class="stat">
                            <h3>{low_count}</h3>
                            <p>آسیب‌پذیری کم</p>
                        </div>
                        <div class="stat">
                            <h3>{len(sorted_vulns)}</h3>
                            <p>کل آسیب‌پذیری‌ها</p>
                        </div>
                    </div>
                </div>
                
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterVulns('all')">همه</button>
                    <button class="filter-btn" onclick="filterVulns('high')">بحرانی</button>
                    <button class="filter-btn" onclick="filterVulns('medium')">متوسط</button>
                    <button class="filter-btn" onclick="filterVulns('low')">کم</button>
                </div>
                
                <h2>🚨 جزئیات آسیب‌پذیری‌ها</h2>
        """
        
        for vuln in sorted_vulns:
            payload_html = f'<div class="payload"><strong>Payload:</strong> {vuln["payload"]}</div>' if vuln['payload'] else ''
            html_content += f"""
            <div class="vulnerability {vuln['severity'].lower()}" data-severity="{vuln['severity'].lower()}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3>{vuln['type']}</h3>
                    <span class="severity {vuln['severity'].lower()}">{vuln['severity']}</span>
                </div>
                <p><strong>URL:</strong> <span class="url">{vuln['url']}</span></p>
                <p><strong>توضیحات:</strong> {vuln['description']}</p>
                <p><strong>زمان کشف:</strong> {vuln['timestamp']}</p>
                {payload_html}
            </div>
            """
        
        html_content += """
                <script>
                    function filterVulns(severity) {
                        const vulns = document.querySelectorAll('.vulnerability');
                        const buttons = document.querySelectorAll('.filter-btn');
                        
                        buttons.forEach(btn => btn.classList.remove('active'));
                        event.target.classList.add('active');
                        
                        vulns.forEach(vuln => {
                            if (severity === 'all' || vuln.dataset.severity === severity) {
                                vuln.style.display = 'block';
                            } else {
                                vuln.style.display = 'none';
                            }
                        });
                    }
                </script>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] گزارش HTML ذخیره شد: {filename}")
        return filename

    async def run_scan(self):
        """اجرای اسکن کامل"""
        print(f"[+] شروع اسکن {self.profile.upper()} برای {self.target_url}")
        print(f"[+] استفاده از {self.threads} concurrent connections")
        
        start_time = time.time()
        
        async with await self.create_session() as session:
            # اجرای همزمان کرال و اسکن
            await asyncio.gather(
                self.crawl_website(session),
                self.scan_suspicious_paths(session)
            )
        
        end_time = time.time()
        
        print(f"\n[+] اسکن تکمیل شد در {end_time - start_time:.2f} ثانیه")
        print(f"[+] تعداد URL های کرال شده: {len(self.crawled_urls)}")
        print(f"[+] تعداد آسیب‌پذیری‌های یافت شده: {len(self.vulnerabilities)}")
        
        # تولید گزارش‌ها
        if self.vulnerabilities:
            csv_file = self.generate_csv_report()
            html_file = self.generate_html_report()
            print(f"[+] پایگاه داده ذخیره شد: {self.db_name}")
            return csv_file, html_file, self.db_name
        else:
            print("[-] هیچ آسیب‌پذیری یافت نشد")
            return None, None, self.db_name

    def __del__(self):
        """بستن اتصال پایگاه داده"""
        if hasattr(self, 'conn'):
            self.conn.close()

async def main():
    parser = argparse.ArgumentParser(description='اسکنر پیشرفته آسیب‌پذیری با Async Crawler')
    parser.add_argument('url', help='URL هدف برای اسکن')
    parser.add_argument('-p', '--profile', choices=['ctf', 'bounty'], default='bounty', 
                       help='پروفایل اسکن (ctf یا bounty)')
    parser.add_argument('-t', '--threads', type=int, default=20, 
                       help='تعداد اتصالات همزمان (پیش‌فرض: 20)')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='timeout برای درخواست‌ها (پیش‌فرض: 10)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    scanner = AdvancedVulnerabilityScanner(
        args.url, 
        args.profile, 
        args.threads, 
        args.timeout
    )
    
    try:
        await scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[!] اسکن توسط کاربر متوقف شد")
    except Exception as e:
        print(f"[-] خطا در اجرای اسکن: {e}")

if __name__ == "__main__":
    asyncio.run(main())
