از یه فایل لیست URL می‌خونه (urls.txt)

روی هر URL تست می‌کنه برای آسیب‌پذیری‌های زیر:

✅ XSS

✅ Open Redirect

✅ SSRF

✅ CSRF (تا حدی قابل تشخیص به صورت passive)

اگر نشونه‌هایی از آسیب‌پذیری پیدا شد، اون رو توی vuln_report.txt ثبت می‌کنه با جزئیات

📁 فایل‌های مورد نیاز:
urls.txt:
هر خط یه URL باشه (با جایگاه پارامتر اگه لازمه)، مثل:

```
https://example.com/page?param=
https://test.com/login?redirect=
http://internal.test/api?url=
```

ذخیره اسکریپت با نام مثلاً: vuln_scanner.py

ایجاد فایل urls.txt و گذاشتن URLها

اجرای اسکن:

```
python3 vuln_scanner.py
```
خروجی در فایل vuln_report.txt ذخیره میشه.

📝 مثال خروجی vuln_report.txt:
```
[XSS] https://test.com/page?param=%3Cscript%3Ealert(1)%3C/script%3E
[Open Redirect] https://victim.com/login?redirect=https%3A%2F%2Fgoogle.com
[Possible SSRF] http://target.com/api?url=http%3A%2F%2F127.0.0.1
[Potential CSRF (missing protection)] https://site.com/updateProfile
```
