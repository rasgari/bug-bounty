یست آسیب‌پذیری‌هایی که بررسی می‌شن:
✅ XSS

✅ Open Redirect

✅ SSRF

✅ CSRF

✅ XXE

✅ SQL Injection

✅ LLM Prompt Injection (در صورت پاسخ‌دهی LLM API)

✅ Account Takeover (محدود به نشانه‌ها)

✅ Code Review (بررسی فایل‌های public مثل .git, .env)

✅ Command Injection

✅ File Upload (بررسی فرم آپلود فایل)

✅ LFI (Local File Inclusion)

✅ IDOR (Insecure Direct Object Reference)

📁 ساختار فایل‌ها
urls.txt → لیست URLها

payloads/ → یک پوشه شامل فایل‌های جدا برای هر آسیب‌پذیری:

```
payloads/xss.txt
payloads/sql.txt
payloads/redirect.txt
payloads/ssrf.txt
```

طرز استفاده:
فایل بالا رو ذخیره کن: super_vuln_scanner.py

پوشه payloads/ بساز:

```
mkdir payloads
```
و فایل‌هایی مثل xss.txt, sql.txt, ... رو توش بذار.

فایل urls.txt بساز با URLهایی که می‌خوای تست کنی.

اجرا:

```
python3 super_vuln_scanner.py
```
✅ خروجی نهایی
فایل خروجی مثل این میشه:

```
[XSS] https://victim.com/page?input=<script>alert(1)</script> | PAYLOAD: <script>alert(1)</script>
[SQL] https://target.com/search?query=' OR '1'='1 | PAYLOAD: ' OR '1'='1
[Open_redirect] https://site.com/redirect?url=https://google.com | PAYLOAD: https://google.com
[CODE_REVIEW] https://site.com/.git/config
```
