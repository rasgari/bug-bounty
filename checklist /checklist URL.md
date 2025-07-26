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
