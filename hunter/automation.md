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
``
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
(منابع مقایسه‌ای و فهرست‌ها را در مطلب‌های مروری ۲۰۲۵ می‌توان دید).
