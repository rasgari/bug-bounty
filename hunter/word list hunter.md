 یک وردلیست پایه و کاربردی برای باگ‌بانتی آماده کرده‌ام که می‌توانید برای فاز کشف مسیرهای مخفی و حساس سایت (Directory/URL Fuzzing) استفاده کنید. این لیست شامل مسیرهای رایج ادمین، بکاپ، فایل‌های پیکربندی و مسیرهای متداول است:

```bash
admin
administrator
login
user
users
dashboard
config
config.php
config.json
backup
backup.zip
backup.tar.gz
db_backup
database
database.sql
uploads
upload
files
private
secret
tmp
temp
test
old
dev
staging
api
api/v1
api/v2
wp-admin
wp-login.php
wp-content
wordpress
.git
.gitignore
.env
.htaccess
robots.txt
sitemap.xml
phpinfo.php
debug
logs
error_log
vendor
composer.json
install
setup
register
reset_password
change_password
logout
profile
account
search
help
support
contact
terms
privacy
```

نکات استفاده:
این لیست را در یک فایل متنی (مثلاً wordlist.txt) ذخیره کنید.

با ابزارهایی مثل ffuf، dirbuster، gobuster یا حتی اسکریپت‌های پایتون روی سایت هدف فازی کنید.

مثال استفاده با ffuf:

```bash
ffuf -u https://targetsite.com/FUZZ -w wordlist.txt -mc 200,301,302
```

توجه کنید که کدهای وضعیت 200 (موفق)، 301 و 302 (ریدایرکت) معمولاً نشان‌دهنده مسیرهای موجود هستند.
