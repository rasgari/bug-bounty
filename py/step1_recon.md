ساختار مرحله اول:
```
webhunter/
├── step1_recon.py          ← مرحله جمع‌آوری اطلاعات
├── urls.txt                ← لیست هدف‌ها
├── out/
│   ├── recon_raw.txt
│   ├── tech_stack.json
```
🐍 کد مرحله اول: step1_recon.py
ابزاری برای استخراج اطلاعات اولیه دامنه (headers، تکنولوژی، وضعیت DNS، WAF احتمالی)

طرز اجرا:
یک فایل urls.txt بساز و دامنه‌ها یا URLها رو توش بنویس:

```
https://example.com
https://target.com/login
```
اجرای اسکریپت:

```
python3 step1_recon.py
```
خروجی‌ها در پوشه out/ ذخیره می‌شن:

recon_raw.txt: خروجی خلاصه

tech_stack.json: خروجی کامل قابل استفاده برای مرحله بعد

========================================================================
