# checklist bug bounty

برای پیشبرد پروژه تست نفوذ وب و تهیه گزارش کامل و حرفه‌ای، ترکیبی از چک‌لیست (Checklist) و برگه تقلب (Cheat Sheet) بسیار موثر است. در ادامه یک چک‌لیست جامع همراه با نکات کلیدی و برگه تقلب برای تست نفوذ وب ارائه می‌کنم که می‌توانید به عنوان راهنما و مرجع در طول تست استفاده کنید.

چک‌لیست جامع تست نفوذ وب (Checklist)
1. قبل از شروع تست نفوذ
تعیین دامنه و محدوده تست (Scope) 

تعیین نوع تست (Black-box, Gray-box, White-box) و دسترسی‌ها

دریافت مجوز قانونی و مستندات لازم

تعیین معیارهای موفقیت و اهداف تست

آماده‌سازی ابزارها و محیط تست (Burp Suite, Nmap, SQLMap و غیره)

2. جمع‌آوری اطلاعات (Reconnaissance)
کشف زیردامنه‌ها (Subdomain Discovery) با ابزارهایی مثل subfinder، Amass

شناسایی فناوری‌ها و CMS (مثلاً وردپرس، جوملا)

اسکن پورت‌ها و سرویس‌ها با Nmap

جمع‌آوری اطلاعات از فایل‌های robots.txt، sitemap.xml

بررسی رکوردهای DNS و WHOIS

3. شناسایی آسیب‌پذیری‌های رایج
تست SQL Injection با SQLMap و تست دستی

تست XSS (Reflected, Stored, DOM-based) با Burp Suite و فازی کردن ورودی‌ها

تست CSRF و بررسی توکن‌های امنیتی

تست Authentication و Authorization (شامل افزایش دسترسی، Account Takeover)

بررسی آسیب‌پذیری‌های File Upload و Remote Code Execution

تست Open Redirect و SSRF

بررسی آسیب‌پذیری‌های مربوط به Session و Cookie

تست امنیت APIها و Web Services (Authentication, Rate Limiting, JWT) 

بررسی تنظیمات امنیتی سرور و HTTP Headers (CSP, HSTS, X-Frame-Options)

4. تحلیل و بهره‌برداری (Exploitation)
استفاده از ابزارهای خودکار و تست‌های دستی برای بهره‌برداری از آسیب‌پذیری‌ها

ثبت دقیق مراحل و نتایج تست‌ها

بررسی امکان دسترسی غیرمجاز به داده‌ها یا سیستم‌ها

5. گزارش‌دهی و پیشنهادات
تهیه گزارش جامع شامل شرح آسیب‌پذیری‌ها، نحوه کشف، ریسک و راهکارهای رفع 

ارائه راهکارهای امنیتی و پیشنهادات بهینه‌سازی

مستندسازی تست‌ها و آماده‌سازی برای بازبینی

برگه تقلب (Cheat Sheet) مهم تست نفوذ وب
موضوع	نکات کلیدی و دستورات مهم	ابزار پیشنهادی
SQL Injection	تست پارامترهای GET/POST، استفاده از sqlmap -u URL	SQLMap, Burp Suite
XSS	تزریق <script>alert(1)</script>، تست Stored و Reflected	Burp Suite, OWASP ZAP
CSRF	حذف توکن CSRF، تغییر هدر Origin/Referer	Burp Suite Repeater
Authentication	تست Brute Force، بررسی MFA، افزایش دسترسی افقی/عمودی	Hydra, Burp Suite
Subdomain Discovery	subfinder -d example.com، جستجو در crt.sh	Subfinder, Amass
Directory/Files	استفاده از wordlist برای fuzzing دایرکتوری‌ها	Dirbuster, ffuf
HTTP Headers	بررسی وجود HSTS, CSP, X-Frame-Options	curl, Burp Suite
SSRF	تزریق آدرس‌های داخلی، استفاده از Burp Collaborator	Burp Suite, curl
Open Redirect	تست پارامترهای redirect، تغییر URL	Burp Suite
Session Management	بررسی HttpOnly, Secure، تست Session Fixation	Burp Suite, OWASP ZAP
API Security	تست Authentication، Rate Limiting، JWT	Postman, Burp Suite
نکات مهم برای موفقیت در تست نفوذ وب
ترکیب تست‌های خودکار و دستی برای پوشش کامل آسیب‌پذیری‌ها ضروری است .

مستندسازی دقیق هر مرحله به گزارش‌نویسی بهتر کمک می‌کند.

تمرکز بر فاز جمع‌آوری اطلاعات (Recon) که بخش عمده موفقیت تست را تضمین می‌کند .

آموزش و به‌روزرسانی مداوم با منابع فارسی و انگلیسی معتبر.

رعایت اخلاق حرفه‌ای و قانونی در تمام مراحل تست.
