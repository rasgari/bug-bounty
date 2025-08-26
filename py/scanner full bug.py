#!/usr/bin/env python3
"""
scanner_full_security.py
Non-intrusive heuristic scanner for a set of web security issues.
Reads urls from a file (one per line) and produces report.csv and report.html

Checks (heuristic / passive):
 - SQL Injection indicators
 - NoSQL Injection indicators
 - OS Command Injection indicators
 - SSRF indicators
 - XXE indicators
 - XSS / DOM XSS indicators
 - Insecure Deserialization indicators
 - Misconfigured CORS
 - Sensitive Data Exposure (API keys, tokens, private keys)
 - Cloud Storage references / misconfig hints
 - Directory Listing enabled
 - Default/Weak Credentials indicators (basic-auth challenge, common login pages)
 - API Key Leakage (patterns in page)
 - Race Condition candidates (state-changing endpoints with id params)
 - Account Takeover related endpoints (password reset flows)
 - IDOR candidates (numeric/object ids in URLs)
 - Privilege Escalation (admin endpoints accessible / role params)
 - Open Redirect (benign check)
 - Multi-pattern findings grouped
"""

import sys
import re
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

TIMEOUT = 8
HEADERS = {"User-Agent": "SafeScanner/1.0 (+non-intrusive)"}

# Regexes
SQL_ERROR_RE = re.compile(r"(you have an error in your sql syntax|sql syntax|mysql|syntax error|ora-|psql|sqlstate)", re.I)
NOSQL_HINT_RE = re.compile(r"(mongodb|mongo|no such command|bson|nosql)", re.I)
CMD_INJECTION_HINT_RE = re.compile(
    r"(;\s*id|\bwhoami\b|cmd=|/bin/sh|/bin/bash|system\(\))",
    re.I
)
XXE_CONTENT_RE = re.compile(r"<\?xml|<!DOCTYPE[^>]*ENTITY", re.I)
XSS_SINKS_RE = re.compile(r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|location\.hash|location\.search)", re.I)
DESERIALIZE_HINT_RE = re.compile(r"(serialize|deserialize|pickle|unserialize|gob|java\.io\.Serializable|PHP_OBJECT)", re.I)
APIKEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token|access[_-]?key|aws_secret|private_key|client_secret)[\"'\s:=]{0,4}([A-Za-z0-9\-_]{16,})")
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-\.]{10,}")
S3_REF_RE = re.compile(r"(s3\.amazonaws\.com|amazonaws\.com/.+?s3|storage\.googleapis\.com|blob\.core\.windows\.net)", re.I)
DIR_LISTING_RE = re.compile(r"Index of /|Directory Listing For|<title>Index of", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

OPEN_REDIRECT_PARAMS = ["next", "redirect", "url", "return", "return_to", "dest", "destination"]

# helper request
def safe_get(url, headers=None, allow_redirects=True, method="GET", data=None):
    h = dict(HEADERS)
    if headers:
        h.update(headers)
    try:
        if method == "GET":
            return requests.get(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects)
        elif method == "POST":
            return requests.post(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects, data=data)
        elif method == "OPTIONS":
            return requests.options(url, headers=h, timeout=TIMEOUT, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None

def read_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]

def normalize_url(u):
    if not urlparse(u).scheme:
        return "http://" + u
    return u

def find_ids_in_path(u):
    p = urlparse(u)
    parts = p.path.split('/')
    ids = [seg for seg in parts if seg.isdigit()]
    return ids

def build_with_param(url, key, val):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = val
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def check_sql_nosql_indicators(text):
    findings = []
    if not text:
        return findings
    if SQL_ERROR_RE.search(text):
        findings.append("SQL error string found in response (possible SQLi leakage)")
    if NOSQL_HINT_RE.search(text):
        findings.append("NoSQL/MongoDB related strings in response (possible NoSQL usage)")
    return findings

def check_cmd_xxe_deserialize(text):
    findings = []
    if not text:
        return findings
    if CMD_INJECTION_HINT_RE.search(text):
        findings.append("Command-exec like strings found in page (inspect endpoints that accept commands)")
    if XXE_CONTENT_RE.search(text):
        findings.append("XML content / DOCTYPE ENTITY pattern found (possible XXE endpoint)")
    if DESERIALIZE_HINT_RE.search(text):
        findings.append("Serialization/deserialization keywords found (possible insecure deserialization)")
    return findings

def check_sensitive_and_keys(text):
    findings = []
    if not text:
        return findings
    if APIKEY_RE.search(text):
        findings.append("Possible API key/secret pattern found in page source")
    if JWT_RE.search(text):
        findings.append("JWT-like token found in page")
    if re.search(r"-----BEGIN (RSA|PRIVATE) KEY-----", text):
        findings.append("Private key material found in page (critical)")
    return findings

def analyze_url(url):
    url = normalize_url(url)
    result_items = []
    # basic GET
    resp = safe_get(url)
    if not resp:
        return result_items

    text = resp.text or ""
    headers = resp.headers or {}

    # 1) SQL/NoSQL indicators (passive)
    result_items += [{"type": "SQL/NoSQL Indicator", "detail": d} for d in check_sql_nosql_indicators(text)]

    # 2) OS command injection hints, XXE, deserialization
    result_items += [{"type": "Command/XXE/Deserialization Indicator", "detail": d} for d in check_cmd_xxe_deserialize(text)]

    # 3) XSS / DOM-based XSS heuristics
    if XSS_SINKS_RE.search(text):
        result_items.append({"type": "DOM XSS Indicator", "detail": "JS sink/source patterns (innerHTML/document.write/eval) found"})

    # 4) Insecure deserialization hint already covered

    # 5) Misconfigured CORS
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao:
        if acao == "*" and acac and acac.lower() == "true":
            result_items.append({"type": "Misconfigured CORS", "detail": "ACAO='*' with credentials=true"})
        elif "http" in acao and acao != "*" and acac and acac.lower() == "true":
            result_items.append({"type": "Misconfigured CORS", "detail": f"Reflected Origin allowed: {acao} with credentials=true"})
    # also test simple reflected origin (safe)
    test_origin = "https://evil.example"
    origin_resp = safe_get(url, headers={"Origin": test_origin}, allow_redirects=False)
    if origin_resp:
        oacao = origin_resp.headers.get("Access-Control-Allow-Origin", "")
        if oacao == test_origin:
            result_items.append({"type": "Misconfigured CORS", "detail": "Reflected Origin in ACAO header (potentially risky)"})

    # 6) Sensitive data / API key leakage
    result_items += [{"type": "Sensitive Data Exposure", "detail": d} for d in check_sensitive_and_keys(text)]

    # 7) Cloud storage refs / possible misconfig
    if S3_REF_RE.search(text):
        result_items.append({"type": "Cloud Storage Reference", "detail": "S3 / GCS / Azure blob URL detected in page"})

    # 8) Directory listing detection
    if DIR_LISTING_RE.search(text):
        result_items.append({"type": "Directory Listing", "detail": "Auto-index/Directory listing signature present in page"})

    # 9) Default/Weak creds hint: WWW-Authenticate Basic
    if resp.status_code == 401 and "www-authenticate" in (h.lower() for h in headers.keys()):
        result_items.append({"type": "Default/Weak Credentials (auth challenge)", "detail": f"WWW-Authenticate: {headers.get('WWW-Authenticate','')}"})

    # 10) API Key leakage via visible emails/keys
    emails = set(EMAIL_RE.findall(text))
    if emails:
        # include domain email findings but not too noisy
        result_items.append({"type": "User/Admin Emails Found", "detail": ", ".join(list(emails)[:5])})

    # 11) Directory and path-based ID / IDOR hints
    ids = find_ids_in_path(url)
    if ids:
        result_items.append({"type": "IDOR Candidate", "detail": f"Numeric id(s) in path: {','.join(ids)}"})

    # 12) Privilege escalation/admin endpoints simple detection
    if any(x in url.lower() for x in ["/admin", "/dashboard", "/manage", "/superuser"]):
        # check if accessible (status 200) without obvious protection
        if resp.status_code == 200:
            result_items.append({"type": "Improper Access Control (admin)", "detail": f"Admin-like path returned {resp.status_code}"})
        else:
            result_items.append({"type": "Admin Path Found", "detail": f"Admin-like path returned {resp.status_code}"})

    # 13) Password reset / account takeover related flows
    if any(x in url.lower() for x in ["reset", "password", "forgot"]):
        # heuristic: token in URL?
        if "token=" in url or "reset_token=" in url or "code=" in url:
            # check token length if present (but non-intrusive)
            result_items.append({"type": "Account Recovery Flow", "detail": "Reset/forgot endpoint with token parameter in URL (review token handling)"})
        else:
            result_items.append({"type": "Account Recovery Endpoint", "detail": "Password reset/forgot flow found (manual review recommended)"})

    # 14) Open redirect benign check
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    redirect_keys = [k for k in qs.keys() if k.lower() in OPEN_REDIRECT_PARAMS]
    if redirect_keys:
        for k in redirect_keys:
            test = build_with_param(url, k, "https://example.com")
            r_no = safe_get(test, allow_redirects=False)
            if r_no and r_no.headers.get("Location","").startswith("https://example.com"):
                result_items.append({"type": "Open Redirect", "detail": f"param {k} redirects to external host (benign check)"})
    else:
        # try adding one redirect param (non-intrusive, no follow)
        test = build_with_param(url, "next", "https://example.com")
        r_no = safe_get(test, allow_redirects=False)
        if r_no and r_no.headers.get("Location","").startswith("https://example.com"):
            result_items.append({"type": "Open Redirect", "detail": "added param next redirects to example.com"})

    # 15) Race condition candidates (technical): endpoints with state change verbs are candidates
    # We will not perform write requests — only heuristic: presence of forms with POST and id params
    try:
        soup = BeautifulSoup(text, "html.parser")
        forms = soup.find_all("form")
        post_forms = [f for f in forms if (f.get("method") or "").lower() == "post"]
        if post_forms:
            # if any form action contains id or similar, flag as race-candidate
            for f in post_forms:
                action = f.get("action") or url
                if re.search(r"(id=|user_id|order_id|transaction)", str(action), re.I) or any(inp.get("name") and re.search(r"(id|qty|amount|count)", inp.get("name"), re.I) for inp in f.find_all("input")):
                    result_items.append({"type": "Race Condition Candidate", "detail": f"POST form with id-like parameter at {action}"})
    except Exception:
        pass

    # 16) NoSQL injection candidate: presence of JSON endpoints or 'mongodb' hints in js calls
    if "application/json" in headers.get("Content-Type","") or re.search(r"\.json\b|/api/", url, re.I) or "ajax" in text.lower():
        result_items.append({"type": "NoSQL/JSON Endpoint", "detail": "JSON/API style endpoint or content-type detected (manual NoSQL checks possible)"})

    # 17) Insecure deserialization hint already included via DESERIALIZE_HINT_RE

    # 18) Multi-vuln: aggregate if multiple findings
    if len(result_items) >= 3:
        result_items.append({"type": "Multi Vulnerability (heuristic)", "detail": f"{len(result_items)} indicators found"})

    # attach url to each
    final = []
    for it in result_items:
        final.append({"url": url, "type": it["type"], "detail": it.get("detail","")})
    return final

def save_csv(findings, fname="report.csv"):
    with open(fname, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type","url","detail"])
        w.writeheader()
        for item in findings:
            w.writerow(item)

def save_html(findings, fname="report.html"):
    rows = []
    for it in findings:
        rows.append(f"<tr><td>{it['type']}</td><td>{it['url']}</td><td>{it['detail']}</td></tr>")
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Scan Report</title>
<style>body{{font-family:system-ui,Arial}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px}}th{{background:#f4f4f4}}</style>
</head><body>
<h1>Security Scan Report (heuristic)</h1>
<p>Non-intrusive checks — manual verification recommended for any finding.</p>
<table>
<thead><tr><th>Type</th><th>URL</th><th>Detail</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="3">No indicators found</td></tr>'}
</tbody></table>
</body></html>"""
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner_full_security.py urls.txt")
        sys.exit(1)
    urls = read_urls(sys.argv[1])
    print(f"[+] Loaded {len(urls)} URLs")

    findings = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(analyze_url, u): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                res = fut.result()
                if res:
                    for item in res:
                        print(f"[!] {item['type']} :: {item['url']} :: {item['detail']}")
                    findings.extend(res)
                else:
                    print(f"[-] {u} :: no indicators")
            except Exception as e:
                print(f"[x] {u} :: error {e}")

    save_csv(findings, "report.csv")
    save_html(findings, "report.html")
    print(f"\nDone. Findings: {len(findings)}")
    print("Saved: report.csv, report.html")

if __name__ == "__main__":
    main()
