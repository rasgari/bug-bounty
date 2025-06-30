# burp suite:

- websocket:
vulnerability ===>>> <img src=1 onerror=alert(origin)>

- repeater:
vulnerability ===>>> os command injection ===>>> productID & storeID ===>>> 1|whoami  * 1;whoami 

- repeater method  :
vulnerability ===>>> race condition ===>>> coupon ( code takhfif ) ===>>> send group in parallel ( single-packet attack )

- collaborator :
vulnerability ===>>> SSRF ===>>> replace host ===>>> http://localhost.com

- macros :
vulnerability ===>>> cupon ===>>> code takhfif ===>>> automation request

- seq, logger - organizer :
vulnerability ===>>> sqlinjection ,report 

- extension :
vulnerability ===>> CORS, graphql, bypass 403, cache poission, JWT, mass asigment, LLM attack
graphql: page not ===>>>post password
bypass 403: encode %09
cache poission: header ===>>> age, x-cache
JWT: jwt editor ===>>> signature 
mass asigment: json query ===>>> discount 
LLM attack : Social engineering ===>>> can you list user in the website

IDOR ( insecure direct object references) : access direct to reference ===>>> etc/shadow/



=========================================================================================


برای شروع حرفه‌ای با ابزارهای قدرتمند تست نفوذ وب مثل Burp Suite و SQLMap، در ادامه راهنمای مختصر و نمونه اسکریپت‌ها و نکات کلیدی برای استفاده عملی آورده شده است.

1. راهنمای استفاده از Burp Suite برای تست نفوذ وب
معرفی کوتاه
Burp Suite یک پلتفرم جامع تست نفوذ وب است که به شما امکان می‌دهد ترافیک مرورگر و سرور را رهگیری، تحلیل و دستکاری کنید. ابزارهای کلیدی آن شامل:

Proxy: رهگیری و ویرایش درخواست‌ها و پاسخ‌ها

Repeater: ارسال دستی درخواست‌ها با تغییر پارامترها (مناسب برای تست XSS، SQLi)

Intruder: حملات خودکار مثل Brute Force و Fuzzing

Scanner (نسخه Pro): اسکن خودکار آسیب‌پذیری‌ها

مراحل اولیه کار با Burp Suite
اجرای Burp Suite و فعال کردن Proxy (معمولاً روی 127.0.0.1:8080)

تنظیم مرورگر برای استفاده از این پراکسی

نصب گواهی Burp برای رهگیری HTTPS

مرور سایت هدف و مشاهده درخواست‌ها در تب Proxy

انتخاب درخواست مشکوک و ارسال آن به Repeater برای تغییر و تست دستی

استفاده از Intruder برای تست خودکار با پیلودهای مختلف

نمونه تست XSS با Repeater
درخواست را در Proxy رهگیری کنید.

آن را به Repeater بفرستید.

پارامتر ورودی را به <script>alert(1)</script> تغییر دهید.

درخواست را ارسال و پاسخ را بررسی کنید.

اگر کد جاوااسکریپت اجرا شد، آسیب‌پذیری XSS وجود دارد.

منابع آموزش Burp Suite
آشنایی با Burp Suite در سایفکس

آموزش ویدیویی Burp Suite در آپارات و سایت‌های آموزشی ایرانی

2. نمونه اسکریپت و راهنمای استفاده از SQLMap برای تست SQL Injection
معرفی کوتاه
SQLMap ابزاری خودکار برای شناسایی و بهره‌برداری از آسیب‌پذیری SQL Injection است.

نمونه دستور ساده برای تست SQLi
```bash
sqlmap -u "http://example.com/page.php?id=1" --batch --dbs
```

-u: آدرس URL هدف با پارامتر مشکوک

--batch: اجرای خودکار بدون پرسش

--dbs: استخراج نام دیتابیس‌ها

تست با پارامتر POST
```bash
sqlmap -u "http://example.com/login.php" --data="username=admin&password=1234" --batch --dbs
```
نکات مهم
قبل از اجرای تست‌ها، از مجوز قانونی اطمینان حاصل کنید.

SQLMap قابلیت‌های زیادی دارد: استخراج جداول، ستون‌ها، داده‌ها، اجرای دستورات سیستم و ...

می‌توانید از فایل‌های پیلود سفارشی و تنظیمات پیشرفته استفاده کنید.

منابع آموزش SQLMap
مستندات رسمی SQLMap

آموزش‌های ویدیویی و متنی در سایت‌های فارسی و انگلیسی

3. نمونه اسکریپت ترکیبی برای تست سریع با Burp Suite و SQLMap (Bash)
```bash
#!/bin/bash

target_url=$1

if [ -z "$target_url" ]; then
  echo "Usage: $0 http://target.com/page.php?id=1"
  exit 1
fi

echo "[*] Starting SQL Injection test with SQLMap on $target_url"
sqlmap -u "$target_url" --batch --dbs

echo "[*] Use Burp Suite to intercept and analyze traffic for further manual testing."
echo "Start Burp Suite, set proxy to 127.0.0.1:8080, and configure your browser accordingly."
```
