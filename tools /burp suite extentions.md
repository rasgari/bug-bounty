# extentions:

- logger++
- Autorize
- ActiveScan++
- Collaborator



افزونه‌های Burp Suite واقعاً سرعت و دقت تست نفوذ رو بالا می‌برن، مخصوصاً برای پیدا کردن باگ‌های P1 (Critical). بذار مهم‌ترین‌هاشون رو برات یکی‌یکی توضیح بدم:

🔹 Logger++

مثل یه Wireshark داخل Burp عمل می‌کنه.

همه‌ی Request/Response ها رو لاگ می‌گیره (حتی وقتی توی Target یا HTTP history حذف بشن).

برای تحلیل جریان درخواست‌ها، Session Hijacking، تست IDOR و بررسی داده‌ها خیلی به‌کار میاد.

معمولاً به صورت پایه‌ای برای تحلیل‌های اولیه استفاده میشه، ولی مستقیم به P1 ربط نداره؛ بیشتر کمکیه.

🔹 Autorize

یکی از پراستفاده‌ترین افزونه‌ها برای باگ‌های P1.

وظیفه: تست Broken Access Control / IDOR / BOLA.

طوری کار می‌کنه که وقتی لاگین هستی و یه درخواست می‌فرستی، همون درخواست رو با توکن/کوکی کاربر دیگه یا بدون لاگین هم می‌فرسته.

اگر جواب یکی بود ➝ یعنی دسترسی درست کنترل نشده (خطرناک، معمولاً P1).

بیشتر توی Bug Bounty برای IDOR / BOLA / Privilege Escalation استفاده میشه.

🔹 ActiveScan++

نسخه‌ی تقویت‌شده‌ی اسکنر داخلی Burp.

Payloadهای اضافه برای تست XSS، SQLi، Command Injection و...

بیشتر برای پیدا کردن Injectionهای High یا Critical استفاده میشه.

البته چون اسکن فعاله، توی برنامه‌های Bug Bounty همیشه توصیه نمی‌شه (بعضی برنامه‌ها فقط Passive Scan می‌خوان).

بیشتر برای SQLi, RCE, Deserialization کمک می‌کنه.

🔹 Collaborator Everywhere

افزونه‌ای برای استفاده از Burp Collaborator.

درخواست‌ها رو دستکاری می‌کنه تا ببینه سرور با یه سرور خارجی تعامل می‌کنه یا نه.

کمک به کشف SSRF, Blind XSS, Blind SQLi, OOB RCE.

خیلی مهمه برای باگ‌های P1 که Blind هستن و نشونه‌ای توی Response نمی‌دن.

مثال: درخواست DNS یا HTTP به دامنه Collaborator = آسیب‌پذیری P1 (مثلاً SSRF).

✅ جمع‌بندی – برای باگ‌های P1 بیشتر این‌ها استفاده میشن:

Autorize → برای Broken Access Control / IDOR / BOLA (خیلی حیاتی)

Collaborator Everywhere → برای SSRF / Blind XSS / Blind SQLi / RCE

ActiveScan++ → برای SQLi / Command Injection / XSS (کمک‌اسکنر قوی)

Logger++ → پشتیبانی و تحلیل (نه مستقیم برای P1، ولی ابزار پایه‌ایه)


=========================================================


# 🔑 افزونه‌های مهم Burp Suite و کاربردهاشون

| افزونه (Extension)       | کاربرد اصلی                                                    | نوع باگ‌های مرتبط            | شدت (احتمال P1)       |
|---------------------------|---------------------------------------------------------------|-------------------------------|------------------------|
| **Logger++**              | لاگ‌برداری کامل از Request/Response، تحلیل جریان داده‌ها       | Session Issues, IDOR کمک‌کننده | ⚪ بیشتر P3/P4 (پشتیبانی) |
| **Autorize**              | تست خودکار **Authorization / Access Control**                 | IDOR, BOLA, Privilege Esc.    | 🔴 خیلی زیاد (P1)       |
| **ActiveScan++**          | اسکن فعال پیشرفته با Payloadهای اضافه                          | SQLi, XSS, RCE, Injections    | 🟠 گاهی P1 (بسته به هدف) |
| **Collaborator Everywhere** | تزریق Payload برای تست تعامل با سرور خارجی (OOB Testing)      | SSRF, Blind XSS, Blind SQLi, RCE | 🔴 خیلی زیاد (P1)       |

---

## 📌 خلاصه
- **Autorize** → بهترین ابزار برای کشف باگ‌های **Broken Access Control (IDOR/BOLA)**.  
- **Collaborator Everywhere** → عالی برای باگ‌های **Blind / OOB (مثل SSRF, Blind XSS)**.  
- **ActiveScan++** → کمک به کشف اینجکشن‌ها و آسیب‌پذیری‌های High/Critical.  
- **Logger++** → ابزار پایه‌ای برای تحلیل و بررسی جریان درخواست‌ها (کمکی، نه مستقیم P1).  


=========================================================


🛠 نصب افزونه‌ها در Burp Suite

برو به منوی Extender → BApp Store.

اسم افزونه (مثلاً Autorize یا Logger++) رو جستجو کن.

روی Install بزن → به صورت خودکار نصب میشه.

بعد از نصب، معمولاً تب مخصوص خودش رو توی Burp می‌بینی (مثلاً تب Autorize یا Logger++).

📌 نحوه استفاده و پیدا کردن آسیب‌پذیری‌ها
🔴 1. Autorize (برای Access Control / IDOR / BOLA)

چی کار می‌کنه؟
هر درخواست تو رو دوباره با یک کوکی/توکن دیگه (یا بدون لاگین) می‌فرسته.

چطور استفاده کنی؟

یه اکانت Admin و یه اکانت User معمولی بساز.

کوکی اکانت User رو کپی کن و توی تب Autorize بذار.

حالا Burp وقتی درخواست با اکانت Admin می‌فرستی، همون رو با کوکی User هم می‌فرسته.

اگه پاسخ‌ها یکی بود (یا اطلاعات حساس لو رفت) → Broken Access Control → P1

✅ کاربرد: پیدا کردن IDOR، BOLA، Privilege Escalation.

🔴 2. Collaborator Everywhere (برای Blind باگ‌ها مثل SSRF / Blind XSS)

چی کار می‌کنه؟
هدرها و ورودی‌ها رو دستکاری می‌کنه تا ببینه سرور با سرور خارجی (Collaborator) ارتباط می‌گیره یا نه.

چطور استفاده کنی؟

افزونه رو فعال کن.

درخواست‌ها رو مرور کن (Proxy / Repeater).

اگر توی Burp Collaborator client دیدی یه DNS/HTTP callback برگشت → یعنی آسیب‌پذیری داری.

✅ کاربرد: SSRF، Blind XSS، Blind SQLi، RCE (Out-of-Band).

🟠 3. ActiveScan++ (Injectionها)

چی کار می‌کنه؟
همون اسکنر Burp هست ولی با payloadهای قوی‌تر.

چطور استفاده کنی؟

یه درخواست مشکوک (مثلاً پارامتر id=123) رو بفرست به Active Scan.

ActiveScan++ پارامترها رو با payloadهای خودش تست می‌کنه.

اگر آسیب‌پذیری مثل SQLi یا XSS باشه توی Issues نشون میده.

✅ کاربرد: SQL Injection، Command Injection، XSS، Deserialization.

⚪ 4. Logger++ (پشتیبان و تحلیلگر)

چی کار می‌کنه؟
همه‌ی Request/Responseها رو ذخیره می‌کنه (حتی اگه توی HTTP history پاک بشن).

چطور استفاده کنی؟

برو تب Logger++ → همه‌ی درخواست‌ها لاگ میشن.

می‌تونی فیلتر کنی (مثلاً فقط درخواست‌های POST).

برای پیدا کردن پارامترهای حساس، Session hijacking، تحلیل IDOR خیلی مفیده.

✅ کاربرد: پشتیبانی و تحلیل. (مستقیم P1 نیست، ولی کمک زیادی می‌کنه).



=========================================================


🟢 سناریو ۱: کشف IDOR با Autorize
🎯 هدف

یک سایت فروشگاه اینترنتی که دو نوع کاربر داره:

User عادی (می‌تونه فقط سفارش خودش رو ببینه)

Admin (می‌تونه سفارش همه رو ببینه)

🛠 مراحل

با اکانت Admin لاگین کن.

وقتی میری به /orders/1234 → می‌بینی سفارش کاربر دیگه رو.

Burp → تب Autorize رو باز کن.

کوکی/توکن کاربر User رو بذار داخلش.

حالا وقتی با اکانت Admin روی /orders/1234 کلیک می‌کنی، Autorize همون درخواست رو با کوکی User می‌فرسته.

نتیجه:

اگر User هم تونست جواب مشابه بگیره (سفارش کسی دیگه رو ببینه) → Broken Access Control (IDOR / BOLA) → P1

در Autorize لیست درخواست‌ها رو می‌بینی، رنگ قرمز/سبز نشون میده تفاوتی هست یا نه.

✅ توی باگ‌بانتی: همین میشه یه گزارش P1 خیلی ارزشمند.

🟢 سناریو ۲: کشف SSRF با Collaborator Everywhere
🎯 هدف

یک اپلیکیشن فرم آپلود داره که توش باید URL عکس پروفایل بدی:
POST /upload

```
{ "image_url": "https://example.com/avatar.jpg" }
```
🛠 مراحل

افزونه Collaborator Everywhere رو فعال کن.

این افزونه به صورت خودکار توی هدرها و پارامترها payloadهای دامنه‌ی Burp Collaborator رو تزریق می‌کنه.

درخواست /upload رو با پارامتر image_url ارسال کن.

حالا برو به Burp → Collaborator Client.

اگر درخواست DNS یا HTTP به دامنه‌ی Collaborator برگشت → یعنی سرور رفته URL رو ریزالو کرده.

نتیجه:

یعنی میشه به سرور دستور داد هر آدرسی رو باز کنه (مثلاً http://169.254.169.254/ برای metadata AWS).

این یعنی SSRF → P1.

✅ توی باگ‌بانتی: SSRF خیلی خطرناکه چون ممکنه منجر به RCE یا Data Leak بشه.

=========================================================

