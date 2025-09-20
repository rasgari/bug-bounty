# Google Dorking — Cheat Sheet (اپراتورهای مهم)

## پایه‌ای
- `site:example.com`  
  محدود کردن جستجو به یک دامنه

- `inurl:admin`  
  جستجو در URL برای کلمهٔ admin

- `intitle:"index of"`  
  پیدا کردن directory listing

- `filetype:pdf` / `filetype:env`  
  جستجوی نوع فایل (PDF, env, sql, log, xlsx ...)

- `intext:"password"`  
  صفحاتی که در متن‌شان کلمهٔ password وجود دارد

- `allinurl: login.php user`  
  همه این کلمات باید در URL باشند

- `cache:example.com`  
  نسخهٔ cached گوگل برای یک سایت

## پیشرفته / ترکیبی (مثال‌های عملی)
- صفحات لاگین / مدیریت:
```
site:target.com inurl:admin OR inurl:login
```

- فایل پیکربندی حاوی credential:

```
site:target.com filetype:env OR filetype:ini "DB_PASSWORD" OR "DB_USER"
```

- فایل‌های بکاپ یا دایرکتوری لیست:

```
site:target.com "index of" "backup"
```

- فایل‌های دیتابیس/اس‌کیو‌ال با محتویات حساس:

```
site:target.com filetype:sql "password" OR "credential"
```

- لاگ‌ها یا فایل متنی با پسورد:

```
filetype:log intext:password site:target.com
```

## نکات ایمنی / اخلاقی
- فقط روی دامنه‌هایی کار کن که **اجازه** داری (scope و written permission).  
- نتایج حساس را امن نگه‌دار و قبل از افشا با مالک هماهنگ کن.  
- دُرک‌ها را برای ری‌مدیشن (پاک‌سازی/تصحیح) استفاده کن، نه سوءاستفاده.

## منابع و مراجع
```
- GHDB (Google Hacking Database) — Exploit-DB.

- کتاب: *Google Hacking for Penetration Testers* — Johnny Long.
- OSINT Framework — فهرست ابزارها و منابع OSINT.
```

---

اپراتورهای گوگل (دُرک‌های پایه — Cheat-sheet)

این اپراتورها را ترکیب کن تا دُرک‌های قدرتمند بسازی:

site:example.com — محدود کردن جستجو به یک دامنه

inurl:admin — URL حاوی کلمهٔ admin

intitle:"index of" — صفحات Directory listing

filetype:pdf یا ext:pdf — جستجوی نوع فایل

intext:"password" — صفحاتی که در متن‌شان کلمهٔ password آمده

allinurl: login.php user — تمام کلمات در URL

cache:example.com — نسخهٔ کش شدهٔ گوگل

related:example.com — سایت‌های مرتبط

```
site:example.com inurl:wp-admin
site:example.com "index of" "backup"
filetype:env intext:DB_PASSWORD
site:gov filetype:pdf "password" OR "credential"
```

تمرین و مثال‌های کوچک (قابل اجرا)

پیدا کردن صفحات admin:
```
site:target.com inurl:admin OR inurl:login
```

پیدا کردن فایل‌های بکاپ:
```
site:target.com intitle:"index of" "backup"
```

پیدا کردن فایل‌های حاوی کلید/پیکربندی:
```
site:target.com filetype:env OR filetype:ini OR filetype:cfg "DB_PASSWORD" OR "password"
```

پیدا کردن فایل‌های Word/Excel که ممکن است creds داشته باشند:
```
site:target.com filetype:xls OR filetype:docx intext:password
```

---

