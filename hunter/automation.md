## automation

اتوماسیون = جمع‌آوری سریع سطح حمله (recon) → کشف نقاط ورودی (discovery) → اسکن خودکار با قالب‌ها/پِی‌لودها → فاز فازی/فاز هدفمند (fuzzing) → صحت‌سنجی و اکسپلویت دستی → تریز / گزارش. همیشه ترکیب اتومات و مانوال بهترین نتیجه رو میده.

1) ابزارهای کلیدی (هرکدوم برای چه‌کاره)

Recon / subdomain:
```
amass, subfinder, massdns — پیدا کردن ساب‌دومین‌ها و دامنه‌های مرتبط.
```
جمع‌آوری URL/آرشیو:
```
waybackurls, gau, gospider — آدرس‌های قدیمی/آشکار شده.
```
فهرست‌/دایرکتوری:
```
ffuf, dirsearch, gobuster — دایرکتوری/فایل‌های مخفی.
```
Fingerprinting & fingerprint templates: nuclei + community templates — برای تشخیص سریع آسیب‌پذیری‌های شناخته‌شده. (مخزن قالب‌ها مرتب آپدیت میشه؛ استفاده از آن بسیار سریع خطاها را نشان می‌دهد). 

اسکن پروکسی/تحلیل ترافیک: 
```
Burp Suite (Community/Professional/DAST) — پروکسی، repeater، intruder، extensions؛ قابلیت ادغام در CI هم داره. 
```


اسکن آزاد / متن‌باز:
```
OWASP ZAP — اسکنر رایگان با Automation Framework و CLI که برای pipeline خوبه. 
```


SQLi / XSS خودکار:
```
sqlmap, dalfox، XSStrike (یا ابزارهای مشابه)
```

فازیِ سریع/هدفمند:
```
wfuzz, ffuf با payload lists و الگوهای gf برای پارامترها.
```
مانیتورینگ قالب‌ها/جداسازی نتایج:
```
jq, httpx, anew, tee برای لاگ‌ها/خروجی‌ها
```


---


2) جریان کاری اتومات‌شده (پایپ‌لاین پیشنهادی — قابل اسکریپت شدن)

جمع‌آوری دامنه/ساب‌دومین‌ها

```
subfinder/amass → dedupe → massdns/httpx برای alive-check.
```
مثال: subfinder -d example.com -o subdomains.txt

جمع‌آوری URLها / صفحات تاریخی
```
waybackurls + gau → filter با httpx برای alive URLs.
```
مثال: cat subdomains.txt | waybackurls | httpx -silent -status-code -o urls.txt

دایرکتوری و فuzzer روی مسیرهای حساس
```
ffuf روی هر host با wordlist مناسب (api, admin, upload, backup).
```
نمونه: ffuf -u https://FUZZ.example.com/FUZZ -w wordlist.txt -mc all -o ffuf.json

اسکن سریع با Nuclei
```
run nuclei against URLs/subdomains using latest templates (tune template severity). Nuclei سریع و قابل دسته‌بندی است؛ جامعه قالب‌ها مرتب ارتقاء می‌یابد. 
```

نمونه: nuclei -l urls.txt -t cves/ -o nuclei-results.txt

DAST / Proxy scanning

```
راه‌اندازی Burp یا ZAP (headless) برای Active Scanning روی محدوده‌های هدف. می‌توان با اسکریپت‌های automation در ZAP یا CI/CLI در Burp اجرا کرد. 
```

فازی / تست پارامترها
```
استخراج پارامترها از URLs با gf pattern‌ها، سپس ffuf/wfuzz زدن روی پارامترهای ورودی.
```
تست‌های خودکار مرتبط با XSS/SQLi
```
dalfox برای XSS روی لیست پارامترها؛ sqlmap برای پارامترهای مشکوک SQL.
```
تریز و کاهش خطا (triage)
```
خودکار: حذف false-positiveهای شناخته‌شده (status codes, responses length).

دستی: بررسی با Burp Repeater, browser، و exploit proof-of-concept.
```
گزارش و خروجی
```
خروجی‌ها را به CSV/HTML/JSON تبدیل کن؛ برای CI می‌توان گزارش‌ها را پیوست کرد (Burp/ZAP هر دو از CI integration پشتیبانی می‌کنند).
```


---

3) مثال‌های واقعی (دستورات پیشنهادی)

Subdomains + live check:
```
subfinder -d example.com -silent | anew subs.txt
httpx -l subs.txt -silent -status-code -o alive.txt
```

Collect URLs:
```
cat alive.txt | gau | waybackurls | sort -u > all_urls.txt
httpx -l all_urls.txt -status-code -o alive_urls.txt
```

Run Nuclei:
```
nuclei -l alive_urls.txt -t cves/ -severities critical,high -o nuclei_findings.txt
```

Fuzz common dirs:
```
ffuf -w /path/wordlists/common.txt -u https://example.com/FUZZ -ac -o ffuf_out.json
```

Dalfox XSS scan (params from gf):
```
cat all_urls.txt | gf xss | dalfox file - --basic
```

ZAP headless baseline (example):
```
zap.sh -daemon -config api.disablekey=true -cmd -quickurl https://example.com -quickout zap_report.html
```

(دستورها را بسته به نسخه‌ی ابزار و نیازتون تنظیم کن).

---

4) ترفندها برای «کمترین زمان» و «کمترین نویز»

پیش‌فیلتر کردن:
```
با httpx فقط URLهای alive را بفرست به اسکنرها تا زمان تلف نشه.
```
استفاده از templates/پریست‌ها: 
```
Nuclei و ZAP quick scans را روی الویت‌های critical/high بزن. (قالب‌های Nuclei مرتب آپدیت میشه — اونا رو pull کن). 
```

توازی/Threading:

```
ابزارهایی مثل ffuf, nuclei, httpx threading دارن — مقدار threads رو متناسب با هدف و rate-limit تنظیم کن.
```
تعیین اولویت (prioritization):
```
ابتدا صفحات لاگین، صفحات آپلود، و endpointهای JSON/API را بررسی کن — این‌ها معمولا بیشترین «اثر» را دارند.
```

reducing false positives: 
```
از پذیرش نتایج با آستانه پایین (e.g. status 200 but tiny body) خودداری کن؛ از response fingerprints استفاده کن.
```

استفاده از browser automation برای جاوااسکریپت‌محور‌ها:
```
Playwright/Puppeteer برای صفحات heavy-JS که scanners معمولی پوشش نمیدن.
```
تست توکن/احراز هویت: 
```
خودکار سازی لاگین و session handling در Burp / ZAP / Playwright تا توکن‌محور endpoints هم پوشش داده بشن.
```


---

5) جایی که اتوماسیون شکست می‌خورد — و چه کار کنیم
```
Business-logic / Authorization issues (IDOR, workflow bugs): اتومات سخت می‌تفهمه؛ اینجا باید manual باشی و تست‌های منطقی بسازی.

False positives & noisy exploits: همیشه دستی تأیید کن و PoC کوچک بساز.

Rate limits / WAF: قبل از اسکن ترافیک را آهسته کن، از IP rotate/proxy استفاده کن، یا حالت passive رو بیشتر کن.
```

---

6) ادغام در CI / Continuous Scanning
```
Burp و ZAP هر دو راه‌های CI دارند: میشه scan توی pipeline (e.g. GitHub Actions, GitLab CI) اجرا کرد و روی change-based scanning تمرکز کرد. این باعث میشه با هر دِپلوی جدید سریع اسکن انجام بشه.
```

---

7) فهرست چک‌لیست اتومات (سریع برای اجرا)
```
subfinder/amass → alive check.

gather URLs (waybackurls/gau).

ffuf روی مسیرها و فایل‌ها.

nuclei با templates آخرین ورژن.

dalfox / sqlmap روی پارامترهای مشکوک.

ZAP/Burp active scan روی محدوده‌های با اهمیت.

manual verification + PoC.

report (CSV/HTML) + issue filing.
```

---

8) منابع و ادامه‌ مطالعه (چند مرجع برای آپدیت بودن)
```
Nuclei templates (GitHub) — مرتب آپدیت میشه؛ ازش استفاده کن. 
```

مستندات Burp CI/Automation — برای ادغام در pipeline. 

```
OWASP ZAP automation docs/releases — برای اجرای headless و Automation Framework.
```
---
