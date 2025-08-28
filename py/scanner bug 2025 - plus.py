#!/usr/bin/env python3
import sys, re, csv, os, signal
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

# ---------- Severity map ----------
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

# ---------- Regex, checks, etc. ----------
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
DOM_XSS_SINKS = re.compile(r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\()")
UPLOAD_HINT = re.compile(r"(?i)(upload|multipart/form-data|file\s*:)") 
RFI_RCE_HINT = re.compile(r"(?i)(exec\(|child_process|spawn\(|system\()")
AUTH_BYPASS_HINT = re.compile(r"(?i)(isAuthenticated\s*:\s*false|bypassAuth|allowAnonymous)")
CONFIG_KEYS = re.compile(r"(?i)(config|settings|env|secret|salt)")
ID_PARAM = re.compile(r"(?i)\b(id|user_id|account_id|order_id|uid|pid)\b")
NUM_IN_URL = re.compile(r"/\d{1,12}(/|$)")

OUTDATED_LIBS = [
    (re.compile(r"jquery-([12])\.\d+(\.\d+)?\.js", re.I), "jquery < 3.5 (XSS CVEs)"),
    (re.compile(r"lodash(?:\.|-)3\.", re.I), "lodash v3 (prototype pollution CVEs)"),
    (re.compile(r"angular(?:\.|-)1\.", re.I), "AngularJS 1.x (EOL)"),
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/config.json", "/settings.json", "/app.config.json",
    "/package.json", "/composer.json", "/yarn.lock", "/pnpm-lock.yaml",
    "/manifest.json", "/sw.js", "/robots.txt",
    "/server.js", "/webpack.config.js", "/vite.config.js", "/next.config.js",
    "/admin", "/administrator", "/login", "/auth", "/hidden", "/secret"
]

# --- تمام توابع اصلی (read_urls, norm_url, http_get, fetch_text, extract_assets, guess_more_assets, analyze_text, check_sensitive_paths, scan_base) بدون تغییر مثل قبل اینجا می‌مونند ---

# --- Save Reports ---
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

# --- Ctrl+C Handler ---
all_findings = []
def save_reports_now():
    all_findings.sort(key=lambda x: x.get("severity",5), reverse=True)
    save_csv(all_findings, "report_gold.csv")
    save_html(all_findings, "report_gold.html")
    print("\n[!] Partial report saved (Ctrl+C) -> report_gold.csv, report_gold.html")

def handle_sigint(sig, frame):
    print("\n[!] Ctrl+C detected, stopping scan...")
    save_reports_now()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

# --- Main ---
def main():
    global all_findings
    if len(sys.argv) != 2:
        print("Usage: python goldmine_scanner.py urls.txt")
        sys.exit(1)

    bases = [norm_url(u) for u in read_urls(sys.argv[1])]
    print(f"[+] Loaded {len(bases)} base URLs")

    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(scan_base, b): b for b in bases}
        for fut in cf.as_completed(futs):
            b = futs[fut]
            try:
                items = fut.result()
                if items:
                    items.sort(key=lambda x: x.get("severity",5), reverse=True)
                    print(f"[!] {b}: {len(items)} findings")
                    all_findings.extend(items)
                else:
                    print(f"[-] {b}: no findings")
            except Exception as e:
                print(f"[x] {b}: error {e}")

    save_reports_now()
    print("\nDone. Full report saved: report_gold.csv, report_gold.html")

if __name__ == "__main__":
    main()
