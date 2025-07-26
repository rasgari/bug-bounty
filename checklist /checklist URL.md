# checklist URL

برای شناسایی URLهایی که احتمال دارد آسیب‌پذیری امنیتی داشته باشند، به دنبال مواردی بودم که:

پارامترهای قابل تزریق دارند (مثل redirect_to=, url=, token=, utm_*).

مکان‌های ادمین یا پلاگین‌های شناخته‌شده وردپرس هستند.

مسیرهایی با داده‌های رمزگذاری‌شده Base64 دارند که ممکن است امکان تزریق یا دسترسی غیرمجاز بدهند.

وجود فایل‌های جاوااسکریپت، JSON یا API endpointهای بدون احراز هویت.

مهم‌ترین URLهایی که پتانسیل آسیب‌پذیری دارند:
1. احتمال Redirect یا Open Redirect
txt
Copy
Edit
http://snapp.ir:80/wp-login.php?redirect_to=http://snapp.ir/wp-admin/&reauth=FUZZ
احتمال آسیب‌پذیری Open Redirect در پارامتر redirect_to.

2. Base64 داخل پارامتر GET — احتمال تزریق یا باز کردن مسیرهای ناامن
txt
Copy
Edit
http://ios.snapp.ir/h/food/?aHR0c... (Base64 string)
این نوع URL‌ با پارامتر ?aHR0c... احتمال اجرای لینک‌های غیرمجاز از طریق Decode کردن دارد.

مثال‌های مشابه:

http://ios.snapp.ir/h/train/?aHR0...

http://snapp.ir/landings/super-app-food?utm_medium=FUZZ

http://services.snapp.ir/wp-includes/js/jquery/jquery.min.js?ver=FUZZ

3. Endpointهای REST API وردپرس (/wp-json/oembed/...)
txt
Copy
Edit
https://club.snapp.ir/wp-json/oembed/1.0/embed?url=https://club.snapp.ir/snapp-drivers-training/...
اگر پارامتر url= بدرستی فیلتر نشده باشد، احتمال XSS یا SSRF دارد.

4. استفاده از token= بدون احراز هویت
txt
Copy
Edit
https://engineering.snapp.ir/authorize-token?expires=1652104148&nightmode=FUZZ
https://engineering.snapp.ir/authorize-token?token=guest&redirectedPub=FUZZ
احتمال سوءاستفاده از توکن در صورت عدم محدودسازی IP یا زمان انقضا.

5. پنل مدیریت بدون احراز هویت مناسب
txt
Copy
Edit
http://promoclub.snapp.ir/wp-admin/?login=FUZZ
http://club.snapp.ir/promoclub/?login=FUZZ
اگر بدون احراز هویت بتوان به پنل دسترسی داشت یا رفتار غیرمنتظره داشت، آسیب‌پذیر است.

پیشنهاد بررسی دقیق‌تر:
برای هر مورد بالا:

بررسی کنید آیا امکان تزریق پارامتر (XSS/Redirect/SSRF) وجود دارد.

ببینید پاسخ سرور در برابر ورودی مخرب (مثل javascript:, data: یا evil.com) چه رفتاری دارد.

تست کنید اگر پارامتر حذف یا تغییر یابد، چه خروجی‌ای می‌دهد.

اگر خواستی، می‌تونم PoC برای تست آسیب‌پذیری هم برات آماده کنم.

آیا می‌خوای که یکی از این URLها رو دقیق‌تر تست کنیم؟

========================================================================================================

بررسی فایل‌های پیوست‌شده به دلیل حجم بسیار زیاد و حجم داده‌های متنی حاوی URLهای متعدد، به صورت خودکار و دقیق امکان‌پذیر نیست. اما برای تعیین اینکه کدام URL می‌تواند شما را به آسیب‌پذیری برساند، معمولاً باید این نکات را بررسی کرد:

آیا URLها شامل پارامترهای ورودی (query parameters) قابل دستکاری هستند؟ مثل action=, id=, token=, redirect_to=, page=, nonce=, login=, preview=, redirect_to=, password=, search=

آیا URL به صفحات ورود (login)، مدیریت (admin)، یا ajax که ممکن است ضعف امنیتی داشته باشند اشاره دارد؟

آیا URLها حاوی پارامترهای رمزنگاری نشده یا توکن‌هایی هستند که امکان تزریق یا دسترسی غیرمجاز فراهم کند؟

URLهایی که شامل کلمات کلیدی آسیب‌پذیری رایج مانند wp-admin, wp-login.php, admin-ajax.php, login.action, authorize-token, redirect_to, nonce, token و ... احتمال آسیب‌پذیری بالاتری دارند.

وجود URLهایی که ممکن است به اسکریپت‌های جاوااسکریپت (js) دسترسی مستقیم می‌دهند می‌تواند خطرناک باشد.

در میان URLهای پیوست‌شده، این نمونه‌ها به طور بالقوه می‌توانند منجر به آسیب‌پذیری باشند (به دلیل داشتن پارامترهای حساس یا دسترسی به بخش‌های مدیریتی):

http://snapp.ir:80/wp-login.php?action=FUZZ

http://snapp.ir:80/panel/wp-login.php?redirect_to=FUZZ

http://club.snapp.ir/promoclub/?login=true&back=FUZZ

https://club.snapp.ir/wp-admin/post.php?post=50669&action=FUZZ

https://club.snapp.ir/wp-json/oembed/1.0/embed?url=https://club.snapp.ir/wp-admin/post.php?post=FUZZ

https://club.snapp.ir/wp-admin/admin-ajax.php?action=FUZZ

http://club.snapp.ir/promoclub/free-corona-test/?login=FUZZ

https://kb.snapp.ir/login.action?os_destination=FUZZ

https://engineering.snapp.ir/authorize-token?expires=...&nightmode=FUZZ

https://pl.snapp.ir/home?token=FUZZ&openedVia=FUZZ

http://snapp.ir:80/wp-json/oembed/1.0/embed?url=http://snapp.ir/contact_us/&format=FUZZ

و URLهایی که شامل پارامترهایی مانند nonce=FUZZ, token=FUZZ, redirect_to=FUZZ, login=FUZZ هستند.

این URLها احتمالاً به صفحات مدیریتی یا با پارامترهای ورودی حساس مرتبط بوده که در صورت نبود تدابیر امنیتی مناسب می‌توانند به آسیب‌پذیری منجر شوند.

برای گزارش آسیب‌پذیری، شما نیاز به تحلیل عمیق‌تر کدهای سمت سرور، پارامترهای ورودی، تاریخچه لاگ‌ها و نحوه اعتبارسنجی و اعتبارسنجی مجوز دسترسی دارید. صرفاً مشاهده URLها کفایت نمی‌کند اما URLs ذکر شده می‌توانند نقطه شروع بررسی دقیق باشند.

اگر بخواهید می‌توانم برخی از URLهای خاص یا پارامترهای مورد نظر را برای تحلیل دقیق‌تر بررسی کنم، لطفاً آنها را مشخص کنید.
