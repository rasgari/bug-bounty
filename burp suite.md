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

==============================================================================================


برای شروع سریع و حرفه‌ای با ابزارهای Burp Suite و SQLMap، در ادامه راهنمای گام‌به‌گام نصب، پیکربندی و منابع آموزشی فارسی و ویدیویی معتبر برای یادگیری بهتر آورده شده است:

راهنمای گام‌به‌گام نصب و پیکربندی Burp Suite
دانلود Burp Suite
نسخه Community رایگان یا نسخه Professional را از سایت رسمی یا منابع معتبر دانلود کنید.

نصب جاوا
Burp Suite نیاز به Java Runtime (نسخه 8 یا بالاتر) دارد. اگر نصب ندارید، ابتدا Java SE Runtime را نصب کنید.

اجرای Burp Suite
فایل JAR را با دستور زیر اجرا کنید:

```bash
java -jar burpsuite_community.jar
```
یا روی فایل JAR دوبار کلیک کنید.

فعال‌سازی Proxy

در Burp Suite به تب Proxy > Options بروید.

مطمئن شوید که Proxy روی آدرس 127.0.0.1 و پورت 8080 فعال است.

تنظیم مرورگر

مرورگر خود را طوری تنظیم کنید که از پراکسی 127.0.0.1:8080 استفاده کند.

برای راحتی، افزونه‌هایی مثل FoxyProxy وجود دارد که این کار را ساده می‌کند.

نصب گواهی Burp برای HTTPS

در مرورگر به آدرس http://burp بروید و گواهی Burp را دانلود و نصب کنید تا بتوانید ترافیک HTTPS را رهگیری کنید.

شروع تست نفوذ

درخواست‌ها را در تب Proxy رهگیری کنید.

درخواست‌ها را به Repeater یا Intruder ارسال کرده و تست‌های دستی و خودکار انجام دهید.

منابع فارسی و ویدیویی برای Burp Suite
مقاله کامل نصب و کرک Burp Suite در w3design.ir

ویدیوی آموزش نصب Burp Suite روی ویندوز - کانال Cyb3rsem در یوتیوب

دوره ویدیویی جامع Burp Suite در learnfiles.com

آموزش نصب و معرفی Burp Suite در آپارات

راهنمای نصب و استفاده از SQLMap
نصب SQLMap

در Kali Linux معمولاً از پیش نصب است.

در سایر سیستم‌ها می‌توانید از گیت‌هاب نصب کنید:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python3 sqlmap.py --help
```
اجرای تست ساده SQL Injection

```bash
python3 sqlmap.py -u "http://target.com/page.php?id=1" --batch --dbs
```

-u: آدرس هدف با پارامتر مشکوک

--batch: اجرای خودکار بدون پرسش

--dbs: استخراج نام دیتابیس‌ها

تست با پارامتر POST

```bash
python3 sqlmap.py -u "http://target.com/login.php" --data="username=admin&password=1234" --batch --dbs
```
امکانات پیشرفته

استخراج جداول، ستون‌ها و داده‌ها

اجرای دستورات سیستم عامل

استفاده از فایل‌های پیلود سفارشی

منابع آموزشی فارسی SQLMap
مستندات و آموزش‌های SQLMap در سایت pentestcore.com

دوره‌های آموزشی تست نفوذ وب در سایت‌های آموزشی ایرانی

ویدیوهای آموزشی کاربردی در یوتیوب و آپارات

نکات مهم برای یادگیری سریع و عملی
تمرین عملی: پس از یادگیری نصب و پیکربندی، روی محیط‌های آزمایشی مثل DVWA یا Juice Shop تمرین کنید.

مطالعه مستمر: هر دو ابزار به‌روزرسانی می‌شوند؛ مستندات رسمی و منابع آموزشی را دنبال کنید.

استفاده از افزونه‌ها و اسکریپت‌ها: در Burp Suite افزونه‌هایی مثل Autorize و Turbo Intruder بسیار کمک‌کننده‌اند.

مجوز قانونی: همیشه قبل از تست نفوذ، مجوز قانونی و اخلاقی داشته باشید.

