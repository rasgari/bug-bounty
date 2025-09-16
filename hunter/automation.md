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
