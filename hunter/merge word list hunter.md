لیست‌های تخصصی‌تر برای CMSهای خاص مثل وردپرس و جوملا و همچنین برای APIها آماده کنم تا در باگ‌بانتی و تست نفوذ وب به شما کمک کند.

نمونه مسیرهای مهم و رایج برای وردپرس (WordPress)
```bash
wp-admin/
wp-login.php
wp-content/
wp-includes/
xmlrpc.php
wp-config.php
readme.html
license.txt
wp-json/
wp-cron.php
wp-comments-post.php
wp-links-opml.php
wp-mail.php
wp-activate.php
wp-signup.php
wp-trackback.php
wp-settings.php
wp-load.php
wp-blog-header.php
wp-register.php
wp-admin/admin-ajax.php
wp-admin/admin-post.php
```
مسیرهای مهم برای جوملا (Joomla)
```bash
administrator/
configuration.php
index.php
templates/
components/
modules/
plugins/
cache/
logs/
tmp/
installation/
language/
media/
images/
libraries/
```
مسیرهای رایج برای APIها و وب‌سرویس‌ها
```bash
api/
api/v1/
api/v2/
api/auth/
api/login/
api/logout/
api/users/
api/admin/
api/docs/
swagger/
openapi/
graphql/
rest/
oauth/
token/
```
نکات مهم برای استفاده از این لیست‌ها:
این مسیرها را در یک فایل متنی ذخیره کنید و با ابزارهای فازی مانند ffuf، gobuster یا dirbuster روی هدف اجرا کنید.

مسیرهای CMSها معمولاً به صورت پیش‌فرض هستند اما ممکن است سایت هدف آن‌ها را تغییر داده باشد؛ بنابراین فازی کردن با لیست‌های عمومی و اختصاصی هر CMS کمک می‌کند مسیرهای مخفی را کشف کنید.

برای APIها، مسیرهای مستندات و احراز هویت اهمیت زیادی دارند و معمولاً هدف حملات قرار می‌گیرند.
