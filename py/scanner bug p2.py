import sys, csv, re, json, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urljoin, parse_qsl, urlunparse
import requests
from bs4 import BeautifulSoup

TIMEOUT = 8
HEADERS = {
    "User-Agent": "SafeAuditor/1.0 (+non-destructive)"
}

OPEN_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_to", "return", "return_to",
    "continue", "dest", "destination", "r", "goto", "out", "callback"
]

def read_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]

def safe_get(url, headers=None, allow_redirects=True, extra_headers=None, method="GET", data=None):
    h = dict(HEADERS)
    if headers:
        h.update(headers)
    if extra_headers:
        h.update(extra_headers)
    try:
        if method == "OPTIONS":
            return requests.options(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects)
        elif method == "POST":
            return requests.post(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects, data=data)
        else:
            return requests.get(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None

def analyze_cors(url):
    """
    تست امن CORS:
      - ارسال Origin ساختگی و بررسی echo شدن آن
      - بررسی ACAO:* + ACAC:true (الگوی ناامن)
    """
    origin = "https://evil.example"
    # Preflight-like OPTIONS
    pre = safe_get(
        url,
        method="OPTIONS",
        extra_headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Test"
        },
        allow_redirects=False
    )
    # Simple GET with Origin
    getr = safe_get(url, extra_headers={"Origin": origin}, allow_redirects=False)

    issues = []
    for resp in [pre, getr]:
        if not resp: 
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            issues.append("ACAO:* with ACAC:true (credentials)")

        if acao == origin and acac.lower() == "true":
            issues.append("Reflected Origin with credentials=true (potentially risky)")

    if issues:
        return {"type": "CORS Misconfiguration", "url": url, "detail": "; ".join(sorted(set(issues)))}
    return None

def analyze_host_header_injection(url):
    """
    درخواست غیرمخرب با Host جعلی و بررسی بازتاب در body/Location.
    """
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    fake_host = "attacker.example"
    # سازگاری: بعضی سرورها به Host نادرست 400 می‌دهند؛ همین هم سیگناله اما ما فقط reflection می‌خواهیم.
    resp = safe_get(url, headers={"Host": fake_host}, allow_redirects=False)
    if not resp:
        return None
    hints = []
    # Location header شامل fake host؟
    loc = resp.headers.get("Location", "")
    if fake_host in loc:
        hints.append("Location header reflected injected Host")

    # body reflection (فقط برچسب؛ ممکن است false positive باشد)
    try:
        if fake_host in resp.text[:200000]:
            hints.append("Body reflected injected Host")
    except Exception:
        pass

    if hints:
        return {"type": "Host Header Injection (reflection)", "url": url, "detail": "; ".join(hints)}
    return None

def analyze_clickjacking(url):
    """
    نبود X-Frame-Options و نبود frame-ancestors در CSP => قابل کلیک‌جکینگ.
    """
    resp = safe_get(url, allow_redirects=False)
    if not resp:
        return None
    xfo = (resp.headers.get("X-Frame-Options") or resp.headers.get("X-Frame-Option") or "").strip()
    csp = (resp.headers.get("Content-Security-Policy") or "").strip()
    fa_missing = ("frame-ancestors" not in csp.lower())
    if (not xfo) and fa_missing:
        return {"type": "Clickjacking", "url": url, "detail": "No X-Frame-Options and no frame-ancestors in CSP"}
    return None

def build_url_with_param(url, key, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def analyze_open_redirect(url):
    """
    فقط تست امن: اگر پارامترهای رایج ریدایرکت وجود ندارند، یکی اضافه می‌کنیم و
    allow_redirects=False تا فقط Location را ببینیم.
    """
    candidates = []
    p = urlparse(url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    present = [k for k in OPEN_REDIRECT_PARAMS if k in qs]
    if present:
        for k in present:
            candidates.append(build_url_with_param(url, k, "https://example.com"))
    else:
        # نسخه‌ای با پارامتر افزودنی (برای تشخیص ساده)
        candidates = [build_url_with_param(url, "next", "https://example.com")]

    for test_url in candidates:
        resp = safe_get(test_url, allow_redirects=False)
        if not resp:
            continue
        loc = resp.headers.get("Location", "")
        if loc.startswith("https://example.com") or loc.startswith("http://example.com"):
            return {"type": "Open Redirect (benign check)", "url": url, "detail": f"Redirect via parameter to example.com ({test_url})"}
    return None

def analyze_xmlrpc(url):
    """
    تشخیص XML-RPC وردپرس به صورت غیرمخرب:
      - /xmlrpc.php پاسخ می‌دهد؟
      - system.listMethods قابل پاسخ است؟
    """
    base = url.rstrip("/")
    endpoint = urljoin(base + "/", "xmlrpc.php")
    # سرآغاز: درخواست GET
    r = safe_get(endpoint, allow_redirects=False)
    if not r:
        return None

    suspect = False
    text = (r.text or "").lower()
    if "xml-rpc" in text or "xmlrpc.php" in endpoint or r.status_code in (200, 405):  # 405: POST only
        suspect = True

    if not suspect:
        return None

    # تست غیرمخرب system.listMethods
    headers = {"Content-Type": "text/xml"}
    body = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
    r2 = safe_get(endpoint, method="POST", headers=headers, data=body, allow_redirects=False)
    if r2 and r2.status_code in (200, 401, 403, 405):
        return {"type": "WordPress XML-RPC (exposed)", "url": endpoint, "detail": f"Status {r2.status_code} on system.listMethods"}
    return None

NUMERIC_PARAM_RE = re.compile(r"(id|uid|user|account|order|invoice|pid|project|cid|gid|group|post|page|item|ticket|ref|doc)\b", re.I)

def analyze_param_tampering(url):
    """
    فقط علامت‌گذاریِ پارامترهای قابل‌ظن برای بازبینی دستی (بدون دستکاری داده حساس).
    """
    p = urlparse(url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    suspects = []
    for k, v in qs.items():
        if NUMERIC_PARAM_RE.search(k) and (v.isdigit() or re.match(r"^\d+$", v)):
            suspects.append(f"{k}={v}")
        if any(k.lower() == s for s in OPEN_REDIRECT_PARAMS):
            suspects.append(f"{k} (redirect-like)")
    if suspects:
        return {"type": "Parameter Tampering (heuristic)", "url": url, "detail": ", ".join(suspects)}
    return None

DOM_SINKS_RE = re.compile(
    r"(location\.hash|location\.search|document\.URL|document\.documentURI|document\.referrer)"
    r".{0,80}(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\()",
    re.I | re.S
)

def analyze_dom_xss(url):
    """
    دانلود HTML و اسکن الگوهای خطرناک برای DOM XSS (استاتیک، احتمال FP دارد).
    """
    r = safe_get(url, allow_redirects=True)
    if not r or not r.text:
        return None
    text = r.text
    if DOM_SINKS_RE.search(text):
        return {"type": "DOM-based XSS (heuristic)", "url": url, "detail": "Potential sink/source pattern found"}
    return None

def analyze_headers_only(url):
    """
    جمع‌بندی چند هدر امنیتی پیشنهادی (informational).
    """
    r = safe_get(url, allow_redirects=False)
    if not r:
        return None
    missing = []
    if not r.headers.get("Content-Security-Policy"):
        missing.append("Content-Security-Policy")
    if not (r.headers.get("X-Frame-Options") or "frame-ancestors" in (r.headers.get("Content-Security-Policy") or "").lower()):
        missing.append("X-Frame-Options/frame-ancestors")
    if not r.headers.get("Referrer-Policy"):
        missing.append("Referrer-Policy")
    if not r.headers.get("X-Content-Type-Options"):
        missing.append("X-Content-Type-Options")
    if not r.headers.get("Strict-Transport-Security") and urlparse(url).scheme == "https":
        missing.append("Strict-Transport-Security")
    if missing:
        return {"type": "Security Headers (missing)", "url": url, "detail": ", ".join(missing)}
    return None

CHECKS = [
    analyze_cors,
    analyze_host_header_injection,
    analyze_clickjacking,
    analyze_open_redirect,
    analyze_xmlrpc,
    analyze_param_tampering,
    analyze_dom_xss,
    analyze_headers_only,
]

def scan_one(url):
    findings = []
    for fn in CHECKS:
        try:
            res = fn(url)
            if res:
                findings.append(res)
        except Exception:
            # هر خطا در یک چک نباید کل اسکن را متوقف کند
            continue
    return findings

def save_csv(findings, path="report.csv"):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "url", "detail"])
        w.writeheader()
        for item in findings:
            w.writerow(item)

def save_html(findings, path="report.html"):
    rows = []
    for item in findings:
        rows.append(f"<tr><td>{item['type']}</td><td>{item['url']}</td><td>{item.get('detail','')}</td></tr>")
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Safe Auditor Report</title>
<style>body{{font-family:system-ui,Arial,sans-serif}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ccc;padding:8px}} th{{background:#f7f7f7;text-align:left}}</style>
</head><body>
<h1>Safe Auditor Report</h1>
<p>Non-destructive checks. Review manually before any active test.</p>
<table>
<thead><tr><th>Type</th><th>URL</th><th>Detail</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="3">No issues flagged.</td></tr>'}
</tbody></table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py urls.txt")
        sys.exit(1)
    urls = read_urls(sys.argv[1])
    print(f"[+] Loaded {len(urls)} URLs")

    findings_all = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(scan_one, u): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                res = fut.result()
                if res:
                    for item in res:
                        print(f"[!] {item['type']} :: {item['url']} :: {item.get('detail','')}")
                    findings_all.extend(res)
                else:
                    print(f"[-] {u} :: OK/No flags")
            except Exception as e:
                print(f"[x] {u} :: error {e}")

    save_csv(findings_all, "report.csv")
    save_html(findings_all, "report.html")
    print(f"\n[✓] Done. Findings: {len(findings_all)}")
    print("Saved: report.csv, report.html")

if __name__ == "__main__":
    main()
