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


