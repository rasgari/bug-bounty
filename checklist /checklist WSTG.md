# checklist WSTG

مقدمه (هدف و دامنه)

راهنمای زیر، چک‌لیستی عملیاتی و قابل اجرا براساس OWASP Web Security Testing Guide (WSTG) است که برای تست امنیت یک وب‌اپلیکیشن یا API طراحی شده — شامل تست‌های اطلاعات‌گیری، پیکربندی و استقرار، مدیریت هویت، مدیریت نشست، ورود داده‌ها، منطق بیزینسی، محافظت از داده‌ها، اجزاء سمت‌کلاینت و وب‌سرویس‌ها و در نهایت گزارش‌دهی. این چارچوب برای تست‌های «gray-box» و «black-box» مناسب است و می‌تواند به عنوان پایه برای گزارش مشاوره‌ای یا گزارش داخلی تیمی به کار رود. 

ساختار کلی چک‌لیست WSTG (خلاصه سطوح — برای هر آیتم: هدف / روش تست / ابزار پیشنهادی / نمونه خروجی)

در ادامه هر بخش را به شکل مختصر اما کاربردی آورده‌ام؛ همین محتوا را می‌توانی برای یک سند ~10 صفحه‌ای (با جزئیات، شواهد و جدول‌ها) گسترش دهی.

1) جمع‌آوری اطلاعات (Information Gathering)

هدف: شناسایی سطوح رو‌به‌رو، بک‌اندها، دامین‌ها، زیر دامنه‌ها، تکنولوژی‌ها، صفحات ادمین، فایل‌های عمومی/حساس.

گام‌ها:

DNS enumeration (subdomain bruteforce، zone transfer check).

HTTP headers و server fingerprinting.

پیدا کردن فایل‌های حساس (robots.txt, .git, backups).

ابزارها: nmap, amass, subfinder, dirsearch, gobuster, whatweb, Wappalyzer (یا افزونه مرورگر).

خروجی نمونه: فهرست زیر‌دامنه‌ها، نرم‌افزارهای شناسایی‌شده و نقاط مدیریتی. 


2) پیکربندی و مدیریت استقرار (Configuration & Deployment Management)

هدف: کشف misconfiguration، اطلاعات لو رفته، نسخه‌های آسیب‌پذیر سرویس‌ها.

گام‌ها:

بررسی TLS (cipher suites, HSTS), سرور‌وب (headers)، file permissions، default creds.

چک کردن open ports و سرویس‌های اضافی.

ابزارها: nikto, sslyze, testssl.sh, nmap با اسکریپت‌ها. 


3) مدیریت هویت (Identity Management)

هدف: بررسی مکانیزم ورود، ثبت‌نام، بازیابی رمز، مولتی‌فکتور، قفل‌سازی حساب.

گام‌ها:

بررسی brute-force protections، enumeration از طریق خطاها، password policy.

تست account takeover و session fixation.

ابزارها: Burp Suite (Intruder/Repeater), Hydra یا Patator برای حملات رمز، اسکریپت‌های سفارشی. 


4) مدیریت نشست (Session Management)

هدف: ارزیابی امن بودن توکن‌ها، کوکی‌ها، زمان انقضا، حملات CSRF و fixation.

گام‌ها:

چک Secure/HttpOnly/SameSite، بررسی token predictability، replay، session timeout.

تست CSRF tokens و توکن‌های دوباره‌استفاده‌شدنی.

ابزارها: Burp Suite, OWASP ZAP. 


5) ورود داده‌ها و اعتبارسنجی (Input Validation)

هدف: کشف XSS، SQLi، Command Injection، LFI/RFI، XML External Entities (XXE)، SSRF.

گام‌ها:

نقاط ورود (GET/POST/Headers/Cookies) را فهرست کن و پک payloadها را اجرا کن.

توجه ویژه به پارامترهایی که به دیتابیس، فایل‌سیستم یا پردازش XML می‌روند.

ابزارها: sqlmap, Burp Scanner/ZAP, xxe-payload-list، nuclei برای شِمای سریع. 


6) صحت منطق بیزینسی (Business Logic)

هدف: کشف فرآیندهای قابل دورزدن (مثلاً گرفتن تخفیف نامحدود، ترتیب مراحل نامناسب، IDOR).

گام‌ها:

تست تغییر ترتیب تراکنش‌ها، tamper پارامترها، بررسی دسترسی‌های عمودی/افقی (IDOR).

ابزارها: Burp Suite (Intruder/Repeater), اسکریپت‌های سفارشی و تست‌های دستی. 


7) محافظت از داده‌ها و رمزنگاری (Data Protection)

هدف: اطمینان از نقل‌وانتقال و ذخیره‌سازی امن اطلاعات حساس (PII, secrets).

گام‌ها:

بررسی TLS، ذخیره‌سازی رمزنگاری‌شده، رمزنگاری ایمن در سمت سرور، عدم افشای secret keys.

ابزارها: بررسی configها، اسکریپت‌های audit، testssl.sh. 


8) کد سمت‌کلاینت و امنیت رابط (Client-Side)

هدف: XSS, CSRF, WAF bypass، امن‌سازی منابع جاوااسکریپت و CSP.

گام‌ها:

بررسی CSP headers، امن‌سازی localStorage، بررسی SRI برای اسکریپت‌های خارجی.

ابزارها: DevTools مرورگر، Burp، ZAP. 


9) API / Web services / Microservices

هدف: تست endpointها، auth (JWT/opaque tokens)، rate-limiting، CORS، input validation روی API.

گام‌ها:

تست فهرست endpointها، بررسی روش‌های HTTP غیراصولی، JWT flaws (alg:none, key leak).

ابزارها: Postman (برای workflowهای نمایشی)، Burp/ZAP, nuclei برای اسکن‌های سریع. 


10) گزارش‌دهی (Reporting) — ساختار پیشنهادی WSTG

ساختار گزارش معمولاً: مقدمه و محدوده، روش تست، خلاصه اجرایی (Executive Summary)، یافته‌ها (برای هر یافته: عنوان، severity، CVSS/OWASP risk rating، شرح، شواهد/اسکرین‌شات/مانده درخواست-پاسخ، ریسک کسب‌وکاری، remediation و priority)، پایان و منابع. WSTG برای قالب گزارش پیشنهادات مفصل دارد. 


ابزارهای پرکاربرد (پشتهٔ معمول تسترها)

فهرست کوتاه از ابزارهایی که بیشتر در چرخه WSTG استفاده می‌شوند، همراه با کاربرد کوتاه:

Burp Suite (Pro/Community) — proxy، repeater، intruder، scanner (Pro). (قابل‌قبول برای تست‌های دستی و خودکار). 


OWASP ZAP — جایگزین رایگان/اوپن‌سورس برای Burp (اسکنر خودکار + ابزارهای دستی). 


Nmap — کشف پورت‌ها و سرویس‌ها.

sqlmap — خودکارسازی تست‌های SQL Injection.

nikto / testssl.sh / sslyze — اسکن سرور و TLS.

nuclei — اسکنر Template-based برای کشف سریع آسیب‌پذیری‌های شناخته‌شده.

amass / subfinder — کشف زیر‌دامنه.

dirsearch / gobuster — کشف دایرکتوری‌ها و فایل‌ها.

Hydra / Patator — حملات brute-force.

Postman یا httpie برای تست APIها.
برای مرور «لیست جامع ابزارها» و منابعِ پیشنهادی در WSTG، Appendix مربوطه را ببین. 


روش‌شناسی اجرایی پیشنهادی (نحوه انجام تست‌ها)

تعریف دامنه و مجوزها (شامل IP ranges، subdomains، environments مثل staging/production).

فاز شناسایی (passive first): جمع‌آوری اطلاعات بدون ارسال payloadهای مخرب.

فاز اسکن خودکار: اجرای ابزارهای اسکن برای نقاط عمومی و پر‌ریسک.

فاز تست دستی دقیق: تست حملات هدفمند و بررسی منطق‌های بیزینسی.

وثیقه‌سازی شواهد: لاگ‌گیری درخواست‌ها/پاسخ‌ها، اسکرین‌شات‌ها، PoC (در صورت نیاز).

ارائه گزارش و رفع خطا: گزارش با اولویت‌بندی و رهنمودهای remediation. 


نمونه ساختار گزارش WSTG (قالب خلاصه — می‌توان مستقیم در ورد / PDF قرار داد)

صفحه اول: عنوان، دامنه تست، تاریخ اجرا، تستر.
خلاصه اجرایی (یک صفحه): وضعیت کلی، تعداد یافته‌ها بر اساس severity (Critical/High/Medium/Low/Info)، ریسک‌های کلیدی و توصیه‌های کوتاه‌مدت.
متدولوژی: ابزارها و تکنیک‌های به‌کار رفته، نوع تست (black/grey/whitebox). 


فصل یافته‌ها: (برای هر یافته یک قالب همانند زیر)

ID: WSTG-XX-YY

Title: SQL Injection in /search endpoint

Severity: High (CVSS: 7.5)

Description: ورودی q در پارامتر GET به درستی پارامترایز نشده و امکان اجرای query دلخواه فراهم است.

Proof / Evidence: درخواست و پاسخ (raw HTTP) + اسکرین‌شات خروجی sqlmap.

Impact: دسترسی به داده‌های حساس، تغییر یا حذف داده‌ها.

Recommendation: استفاده از prepared statements / ORM parameter binding، validation و least-privilege DB account.

Status / Priority: P1 — Fix within 2 weeks.

Appendix: full request/response logs, tools versions, references (link به WSTG و CVEs). 
Infinum

مثال (نمونه خلاصه‌ی چند یافته فرضی — برای نشان دادن قالب)

WSTG-01 — Open TLS ciphers / missing HSTS — Medium — remediation: enable HSTS, disable weak ciphers. (ابزار: testssl.sh)

WSTG-02 — Reflected XSS در /search — High — remediation: output-encoding, CSP. (ابزار: Burp + manual payloads)

WSTG-03 — IDOR در endpoint /orders/{id} — High — remediation: authorization checks server-side.
این‌ها نمونه‌هایی هستند که در گزارش باید request/response و PoC ارائه شود. 


منابع پیشنهادی (مطالعه عمیق و دانلود)

صفحه رسمی WSTG (Latest) — مرجع اصلی و به‌روز. 


WSTG v4.2 (PDF / نسخه پایدار) — برای آرشیو و مراجع آفلاین. 


Appendix ابزارهای WSTG — فهرست ابزارهای پیشنهادی. 


نمونه قالب‌های گزارش / نمونه گزارش‌های عمومی (مثال‌های شرکت‌ها به عنوان الگو). 


مقالات و بلاگ‌های آموزشی (برای یادگیری ابزارها و automation: مقالات Snyk, Cobalt و غیره). 


نکات اجرایی و توصیه‌های حرفه‌ای

ترکیب ابزار + تست دستی: ابزارهای خودکار خطاها را پیدا می‌کنند اما منطق بیزینسی و خطاهای پیچیده را فقط تست دستی می‌یابد. 


تفکیک environments: هرگز بدون مجوز صریح به محیط production حمله سنگین نکن.

مستندسازی کامل: هر یافته باید با شواهد خام (HTTP request/response) و دستورالعمل رفع همراه باشد تا توسعه‌دهنده بتواند مستقلاً اقدام کند. 


به‌روزرسانی منظم: WSTG و ابزارها را مرتب بررسی کن (نسخه‌ها و templates مانند nuclei به‌روز می‌شوند). 
