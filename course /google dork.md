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

