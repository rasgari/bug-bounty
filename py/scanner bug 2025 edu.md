ورودی: urls.txt (هر خط یک URL پایه یا صفحه)

کاری که می‌کند:

صفحه را می‌گیرد، لینک‌ها و فایل‌های JS/JSON/Config را پیدا و دانلود می‌کند

داخل محتوا به‌دنبال کلیدواژه‌های gold-mine می‌گردد (مثل auth, config, settings, runtime, bundle, api, session, …)

الگوهای کلید و توکن، WebSocket، پارامترهای پنهان، Upload، Open Redirect، IDOR و … را با Regex تشخیص می‌دهد

مسیرهای حسّاس متداول (مثل /.env, /config.json, /package.json, /admin, /sw.js, /manifest.json …) را به‌شکل امن چک می‌کند

کتابخانه‌های آشنا (مثل jquery-1.x یا 2.x) را اگر قدیمی باشند هشدار می‌دهد

خروجی: CSV + HTML و به‌ترتیب اهمیت (Severity) مرتب شده

توجه: این ابزار تهاجمی نیست (درخواست‌های خطرناک نمی‌زند). هر یافته یعنی «سرنخ» که باید دستی بررسی شود.

```
pip install requests beautifulsoup4
python goldmine_scanner.py urls.txt
```

```
#!/usr/bin/env python3
import sys, re, csv, os
import concurrent.futures as cf
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": "GoldMineScanner/1.0 (+safe, passive)"}
TIMEOUT = 10
MAX_WORKERS = 24

# ---------- Keyword buckets ----------
GOLD_KEYWORDS = [
    "main","app","runtime","bundle","polyfills","auth","config",
    "settings","local","dev","data","api","session","user",
    "core","client","server","utils","base"
]

# ---------- Severity map (higher = more مهم) ----------
SEVERITY = {
    "Hardcoded Credentials": 10,
    "JWT / API Keys": 10,
    "Authentication Bypass Hint": 9,
    "Sensitive Info Leak": 9,
    "Config/Env Disclosure": 9,
    "Hidden Login/Portal": 8,
    "Outdated Library (CVE-prone)": 8,
    "Dependency/Package Disclosure": 7,
    "Upload Endpoint (potential)": 7,
    "RFI/RCE Hint": 7,
    "Open Redirect (param)": 7,
    "WebSocket Endpoint": 6,
    "Hidden Parameters": 6,
    "IDOR Candidate": 6,
    "Service/Endpoint Map": 5,
}

# ---------- Regex: keys/tokens/emails/urls ----------
AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET = re.compile(r"(?i)aws(.{0,10})?(secret|key).{0,3}[:=]\s*['\"]?([A-Za-z0-9/+=]{30,})")
GCP_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GENERIC_APIKEY = re.compile(r"(?i)(api[_-]?key|token|secret|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]")
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.]{10,}")
BASIC_CRED = re.compile(r"(?i)(username|user|login)\s*[:=]\s*['\"][^'\"\s]{3,}['\"].{0,40}(password|pass|pwd)\s*[:=]\s*['\"][^'\"\s]{3,}['\"]")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
WS_RE = re.compile(r"\b(wss?:\/\/[^\s\"'<>]+)")
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>()]+")
OPEN_REDIRECT_KEYS = re.compile(r"(?i)(redirect|next|return|url|dest|destination)")

# DOM/JS risky sinks (front-end)
DOM_XSS_SINKS = re.compile(r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\()")
# Upload / RFI hints
UPLOAD_HINT = re.compile(r"(?i)(upload|multipart/form-data|file\s*:)") 
RFI_RCE_HINT = re.compile(r"(?i)(exec\(|child_process|spawn\(|system\()")
# Auth bypass hints
AUTH_BYPASS_HINT = re.compile(r"(?i)(isAuthenticated\s*:\s*false|bypassAuth|allowAnonymous)")
# Config/Env disclosure
CONFIG_KEYS = re.compile(r"(?i)(config|settings|env|secret|salt)")
# IDOR
ID_PARAM = re.compile(r"(?i)\b(id|user_id|account_id|order_id|uid|pid)\b")
NUM_IN_URL = re.compile(r"/\d{1,12}(/|$)")

# Outdated libs quick checks (heuristic)
OUTDATED_LIBS = [
    (re.compile(r"jquery-([12])\.\d+(\.\d+)?\.js", re.I), "jquery < 3.5 (XSS CVEs)"),
    (re.compile(r"lodash(?:\.|-)3\.", re.I), "lodash v3 (prototype pollution CVEs)"),
    (re.compile(r"angular(?:\.|-)1\.", re.I), "AngularJS 1.x (EOL)"),
]

# Common sensitive files (safe GET)
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/config.json", "/settings.json", "/app.config.json",
    "/package.json", "/composer.json", "/yarn.lock", "/pnpm-lock.yaml",
    "/manifest.json", "/sw.js", "/robots.txt",
    "/server.js", "/webpack.config.js", "/vite.config.js", "/next.config.js",
    "/admin", "/administrator", "/login", "/auth", "/hidden", "/secret"
]

def read_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]

def norm_url(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def http_get(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True)
        return r
    except requests.RequestException:
        return None

def fetch_text(url):
    r = http_get(url)
    if r is None:
        return None, None
    ctype = r.headers.get("Content-Type","").lower()
    # skip binaries
    if any(b in ctype for b in ["image/","font/","octet-stream","pdf"]):
        return None, r.headers
    return r.text, r.headers

def extract_assets(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    assets = set()
    # JS/JSON/Manifest/CSS
    for tag in soup.find_all(["script","link","a"]):
        src = tag.get("src") or tag.get("href")
        if not src: 
            continue
        full = urljoin(base_url, src)
        if any(full.lower().endswith(ext) for ext in [".js",".mjs",".json",".map",".txt",".config",".env",".lock",".yml",".yaml",".xml",".html",".htm",".css",".wasm",".md"]):
            assets.add(full)
        # also pick query-marked bundles (e.g., main.js?v=)
        if any(k in full.lower() for k in GOLD_KEYWORDS):
            assets.add(full)
    return list(assets)

def guess_more_assets(base_url):
    # try common paths (don’t brute force too much)
    candidates = [
        "/main.js","/app.js","/runtime.js","/bundle.js","/polyfills.js",
        "/static/js/main.js","/static/js/app.js","/assets/app.js",
        "/config.json","/settings.json","/manifest.json","/sw.js",
        "/assets/index.js","/js/app.js","/js/main.js"
    ]
    return [urljoin(base_url, p) for p in candidates]

def analyze_text(url, text, headers):
    findings = []

    def add(kind, detail, evidence=None):
        findings.append({
            "type": kind,
            "url": url,
            "detail": detail,
            "evidence": (evidence or "")[:240],
            "severity": SEVERITY.get(kind, 5)
        })

    # 1) Keys / tokens / creds / JWT
    if AWS_ACCESS.search(text) or AWS_SECRET.search(text) or GCP_KEY.search(text) or GENERIC_APIKEY.search(text) or JWT_RE.search(text):
        add("JWT / API Keys", "Key/Token pattern detected", "…"+JWT_RE.search(text).group(0) if JWT_RE.search(text) else None)

    if BASIC_CRED.search(text):
        add("Hardcoded Credentials", "username/password pattern in source")

    # 2) Sensitive info leak / emails / config hints
    if CONFIG_KEYS.search(text):
        add("Sensitive Info Leak", "Config/Env related strings in client code")

    emails = set(EMAIL_RE.findall(text))
    if emails:
        add("Sensitive Info Leak", f"Emails exposed: {', '.join(list(emails)[:5])}")

    # 3) WebSocket endpoints
    for m in WS_RE.findall(text):
        add("WebSocket Endpoint", f"Found {m}")

    # 4) Hidden parameters / Open redirect params
    if OPEN_REDIRECT_KEYS.search(text):
        add("Open Redirect (param)", "Redirect-like parameter referenced in source (next/return/url/redirect)")

    # 5) Upload endpoints hint
    if UPLOAD_HINT.search(text):
        add("Upload Endpoint (potential)", "Upload/multipart hints in client bundle")

    # 6) RFI/RCE hint (server-side references showing up in bundle)
    if RFI_RCE_HINT.search(text):
        add("RFI/RCE Hint", "Dangerous exec/system/child_process references observed")

    # 7) DOM XSS sinks
    if DOM_XSS_SINKS.search(text):
        add("Sensitive Info Leak", "DOM sinks in client (innerHTML/document.write/eval)")

    # 8) IDOR candidate (id-ish params or numeric ids in path)
    if ID_PARAM.search(text):
        add("IDOR Candidate", "id/user_id/order_id mentioned in client code")
    if NUM_IN_URL.search(url):
        add("IDOR Candidate", "Numeric id in URL path")

    # 9) Auth bypass hint
    if AUTH_BYPASS_HINT.search(text):
        add("Authentication Bypass Hint", "Suspicious auth flags in bundle")

    # 10) Outdated libs quick check
    for rx, msg in OUTDATED_LIBS:
        if rx.search(url) or rx.search(text):
            add("Outdated Library (CVE-prone)", msg)

    # 11) Dependency disclosure
    if "package.json" in url or ("content-type" in (headers or {}) and "json" in (headers.get("Content-Type","").lower())):
        if '"dependencies"' in (text or "") or '"devDependencies"' in (text or ""):
            add("Dependency/Package Disclosure", "package.json-like content visible")

    # 12) Service/endpoint map (collect URLs embedded in code)
    embedded = [m for m in URL_IN_TEXT.findall(text) if not m.endswith((".png",".jpg",".jpeg",".gif",".svg",".webp"))]
    if embedded:
        add("Service/Endpoint Map", f"{min(len(embedded),10)} embedded URLs (sample): {', '.join(embedded[:5])}")

    return findings

def check_sensitive_paths(base_url):
    results = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        r = http_get(url)
        if not r: 
            continue
        code = r.status_code
        if code == 200:
            ctype = r.headers.get("Content-Type","").lower()
            text = r.text if "text" in ctype or "json" in ctype or ctype == "" else ""
            # classify
            if path.startswith("/.env") or path.endswith(".config.js") or path.endswith(".config") or path.endswith(".json"):
                results.append({"type":"Config/Env Disclosure","url":url,"detail":f"{path} accessible (HTTP {code})","evidence":(text[:200] if text else ""), "severity":SEVERITY["Config/Env Disclosure"]})
            elif path in ("/admin","/administrator","/login","/auth","/hidden","/secret"):
                results.append({"type":"Hidden Login/Portal","url":url,"detail":f"Portal path accessible (HTTP {code})","evidence":"", "severity":SEVERITY["Hidden Login/Portal"]})
            elif path == "/package.json":
                results.append({"type":"Dependency/Package Disclosure","url":url,"detail":"package.json readable","evidence":(text[:200] if text else ""), "severity":SEVERITY["Dependency/Package Disclosure"]})
            elif path in ("/sw.js","/manifest.json","/robots.txt"):
                # informational, can reveal hidden routes
                results.append({"type":"Service/Endpoint Map","url":url,"detail":f"{path} accessible","evidence":(text[:200] if text else ""), "severity":SEVERITY["Service/Endpoint Map"]})
        elif code in (401,403):  # existence but protected
            if path in ("/admin","/administrator"):
                results.append({"type":"Hidden Login/Portal","url":url,"detail":f"{path} present but protected (HTTP {code})","evidence":"", "severity":SEVERITY["Hidden Login/Portal"]})
    return results

def scan_base(base_url):
    base_url = norm_url(base_url)
    findings = []

    # 1) fetch base
    text, headers = fetch_text(base_url)
    if text is None and headers is None:
        return findings

    if text:
        findings += analyze_text(base_url, text, headers)

    # 2) extract and guess assets
    assets = set()
    if text:
        for a in extract_assets(base_url, text):
            assets.add(a)
    for g in guess_more_assets(base_url):
        assets.add(g)

    # 3) fetch assets (in parallel, but limit here per base)
    def fetch_and_analyze(u):
        t, h = fetch_text(u)
        if t is None: 
            return []
        return analyze_text(u, t, h)

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(fetch_and_analyze, list(assets)):
            findings.extend(res)

    # 4) sensitive paths check
    findings.extend(check_sensitive_paths(base_url))

    return findings

def save_csv(findings, path="report_gold.csv"):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["severity","type","url","detail","evidence"])
        w.writeheader()
        for it in findings:
            w.writerow({
                "severity": it.get("severity",5),
                "type": it["type"],
                "url": it["url"],
                "detail": it.get("detail",""),
                "evidence": it.get("evidence","")
            })

def save_html(findings, path="report_gold.html"):
    rows = []
    for it in findings:
        rows.append(f"<tr><td>{it.get('severity',5)}</td><td>{it['type']}</td><td>{it['url']}</td><td>{it.get('detail','')}</td><td><pre style='white-space:pre-wrap'>{(it.get('evidence','') or '')}</pre></td></tr>")
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GoldMine Scan Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:20px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}
th{{background:#f7f7f7}}
pre{{margin:0;max-height:160px;overflow:auto}}
.badge{{display:inline-block;padding:2px 6px;border-radius:8px;background:#222;color:#fff;font-size:12px}}
</style></head><body>
<h1>GoldMine Security Scan (passive)</h1>
<p>این گزارش با روش غیرتهاجمی تولید شده است؛ هر یافته نیاز به تأیید دستی دارد.</p>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>URL/Asset</th><th>Detail</th><th>Evidence (snippet)</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'}
</tbody></table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    if len(sys.argv) != 2:
        print("Usage: python goldmine_scanner.py urls.txt")
        sys.exit(1)

    bases = [norm_url(u) for u in read_urls(sys.argv[1])]
    print(f"[+] Loaded {len(bases)} base URLs")

    all_findings = []
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(scan_base, b): b for b in bases}
        for fut in cf.as_completed(futs):
            b = futs[fut]
            try:
                items = fut.result()
                if items:
                    # sort local findings by severity
                    items.sort(key=lambda x: x.get("severity",5), reverse=True)
                    print(f"[!] {b}: {len(items)} findings")
                    all_findings.extend(items)
                else:
                    print(f"[-] {b}: no findings")
            except Exception as e:
                print(f"[x] {b}: error {e}")

    # global sort by severity desc
    all_findings.sort(key=lambda x: x.get("severity",5), reverse=True)
    save_csv(all_findings, "report_gold.csv")
    save_html(all_findings, "report_gold.html")
    print("\nDone. Saved: report_gold.csv, report_gold.html")

if __name__ == "__main__":
    main()



````

اگر می‌خوای سریع‌تر باشه، MAX_WORKERS رو با توجه به پهنای‌باند بالا ببر.

می‌تونی لیست SENSITIVE_PATHS و کلمات کلیدی GOLD_KEYWORDS رو با دامنه/فریمورک خودت شخصی‌سازی کنی.

ماژول Outdated Library فعلاً روی نام فایل‌ها عمل می‌کنه (مثل jquery-1.x). اگر خواستی، می‌تونیم نسخه‌ها را از package.json بخونیم و مقایسه کنیم.

برای Open Redirect، این نسخه فقط وجود پارامترهای redirect-like را علامت می‌زند (تهاجمی نیست). اگر نیاز داشتی نسخهٔ کنترل‌شدهٔ PoC هم اضافه می‌کنم.

