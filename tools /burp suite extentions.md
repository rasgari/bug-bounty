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

