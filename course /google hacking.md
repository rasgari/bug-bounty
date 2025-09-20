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

