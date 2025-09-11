مهم‌ترین مطالب و تکنیک‌ها

در هر فصل، چند نکته و تکنیک مهمی وجود داره که برای تست نفوذ روزمره خیلی به کارت میان:

فصل 2: جمع‌آوری اطلاعات (Intelligence Gathering & Enumeration)

انتخاب استراتژی مناسب برای جمع‌آوری آشکار و پنهان اطلاعات (passive / active)

پیدا کردن Subdomains، بررسی DNS، SSL/TLS، fingerprinting سرور، ورژن‌های نرم‌افزار

استفاده از ابزارها برای جمع-آوری ساختار صفحات، JavaScriptها، APIها، endpointها 
Google Books
+1

فصل 3: Server-Side Injection

انواع SQL Injection (Error-based, Blind, Union)

Command Injection، OS Injection

تزریقات بر روی پایگاه‌داده و نفوذ با پارامترهایی که ورودی‌هاشون مستقیما به DB میرن

فصل 4: Client-Side Injection

XSS (Reflected, Stored, DOM-based)

JS Injection، HTML Injection

آسیب‌پذیری‌هایی که در سمت کلاینت برای دستکاری DOM، سرقت کوکی/توکن یا فیشینگ ظاهر میشن

فصل 5: CSRF

چگونگی کارکرد CSRF و راهکارهای معمول محافظتی مثل توکن‌ها، SameSite، Referer Validation

bypass کردن محافظت‌های ضعیف و حملات ترکیبی با XSS

فصل 7: Authentication / Authorization / SSO

آزمون پارامترهای مربوط به لاگین، پسورد reset، session fixation

SSO و OAuth و OpenID گرفتن چکربازان برای اطمینان از این که اصلاً کسی بتونه توکن کاربری رو دستکاری کنه

Broken Access Control (مثل IDOR, horizontal privilege escalation) 
Google Books

فصل 8: Business Logic Flaws

منطق تجاری نادرست مثل bypass قوانین، فرایندهای خاصی که باید کنترل بشن (مثلاً محدودیت پرداخت، کوپن، فاکتور)

مثال‌هایی که باگ بانتی‌ها معمولاً بهش برخورد می‌کنن

فصل 9: XXE, SSRF, Request Smuggling

XXE: تزریق موجودیت خارجی و آسیب‌هایی که پرونده‌ها، داده‌های داخلی، سرویس‌ها رو تحت تأثیر قرار میدن

SSRF: چگونگی کشفش، بهره‌برداری از آدرس‌های داخلی، metadata service

Request Smuggling: چطور درخواست‌های HTTP مخلوط میشن و چگونه این باعث دور زدن محافظ‌ها یا کشف اطلاعات میشه

فصل 13: Evading Web Application Firewalls (WAFs)

تکنیک‌های دورزدن WAF مثل تغییر هدرها، encoding، chunked encoding، تغییر روش HTTP، استفاده از پارامترهای غیرعادی

چگونه payloadها رو طوری بسازی که فیلتر WAFها رو رد کنن

فصل 14: Report Writing

چطور یافته‌ها رو حرفه‌ای مستندسازی کنی

مفاهیم مانند عنوان مناسب، شرح آسیب‌پذیری، مراحل بازتولید، تاثیر، توصیه‌ها

اهمیت ارایه‌ی مدرک مثل Request / Response / اسکرین‌شات / PoC

✅ نکات کاربردی از کتاب برای عمل در باگ بانتی / تست نفوذ

همیشه با جمع‌آوری کامل اطلاعات شروع کن: endpointها، پارامترها، APIها، تکنولوژی استفاده‌شده

فراتر از Injectionها — باگ‌های منطقی (Business Logic) و کنترل دسترسی معمولاً پیچیده‌تر دیده می‌شن ولی ارزش بالایی دارن

برای SSRF و XXE تنوع payload داشته باش و تست‌های Out-of-Band (Collaborator) انجام بده

برای WAF: تست Encode کردن، تغییر روش حمله، استفاده از محتوای عجیب

مستندسازی کامل: برای P1، شواهد واضح فرستادن جواب غیرمجاز با درخواست تغییر داده شده، لاگ‌ها، تفاوت در پاسخ‌ها و غیره ضروریه
