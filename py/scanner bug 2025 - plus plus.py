#!/usr/bin/env python3
"""
scanner_full_advanced.py
Async-ish threaded passive "goldmine" scanner with:
 - CSV / HTML / JSON outputs
 - Summary report + versions report
 - Subdomain aggregation limited to seeds
 - Progress bar (tqdm)
 - Optional CVE (NVD) and Exploit-DB checks for discovered software/version
 - Safe non-intrusive heuristics
"""

import sys, os, time, json, argparse, signal
import re, csv, datetime
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from collections import defaultdict, Counter

# ---------- Config ----------
HEADERS = {"User-Agent": "GoldMineScanner/advanced/1.0 (+passive)"}
TIMEOUT = 10
DEFAULT_WORKERS = 20
DEFAULT_OUT = "reports"
# Respectful pause for CVE/ExploitDB queries to avoid hammering remote APIs
CVE_QUERY_PAUSE = 1.2
EXPLOITDB_QUERY_PAUSE = 1.2

# ---------- Heuristics / Regex ----------
GOLD_KEYWORDS = set([
    "main","app","runtime","bundle","polyfills","auth","config",
    "settings","local","dev","data","api","session","user",
    "core","client","server","utils","base"
])

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
    "RFI/RCE Hint": 9,
    "Open Redirect (param)": 7,
    "WebSocket Endpoint": 6,
    "Hidden Parameters": 6,
    "IDOR Candidate": 6,
    "Service/Endpoint Map": 5,
    "Version Info": 4,
    "CVE Match": 10,
    "ExploitDB Match": 9
}

AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GENERIC_APIKEY = re.compile(r"(?i)(api[_-]?key|token|secret|client[_-]?secret)[\"'\s:=]{0,4}([A-Za-z0-9\-_]{16,})")
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.]{10,}")
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
    "/.env", "/.env.local", "/config.json", "/settings.json", "/package.json",
    "/composer.json", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/admin", "/login"
]

# ---------- Helpers ----------
def norm_url(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def http_get(url, timeout=TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None

def fetch_text(url):
    r = http_get(url)
    if r is None:
        return None, None
    ctype = r.headers.get("Content-Type","").lower()
    if any(b in ctype for b in ["image/","font/","octet-stream","pdf"]):
        return None, r.headers
    return r.text, r.headers

def extract_assets(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    assets = set()
    for tag in soup.find_all(["script","link","a","img","source"]):
        src = tag.get("src") or tag.get("href") or tag.get("data-src")
        if not src: continue
        if src.startswith("mailto:") or src.startswith("tel:"): continue
        full = urljoin(base_url, src)
        if any(full.lower().endswith(ext) for ext in [".js",".mjs",".json",".map",".txt",".config",".env",".lock",".yml",".yaml",".xml",".html",".htm",".css",".wasm",".md"]):
            assets.add(full)
        if any(k in full.lower() for k in GOLD_KEYWORDS):
            assets.add(full)
    # also find raw URLs in JS/text
    for m in re.findall(r"https?://[^\s'\"()<>]+", html or ""):
        assets.add(m)
    return list(assets)

def guess_more_assets(base_url):
    candidates = ["/main.js","/app.js","/runtime.js","/bundle.js","/polyfills.js","/config.json","/settings.json","/manifest.json","/sw.js","/package.json"]
    return [urljoin(base_url, p) for p in candidates]

def prioritize_asset(url):
    score = 0
    low = url.lower()
    for k in GOLD_KEYWORDS:
        if k in low:
            score += 1
    if any(low.endswith(ext) for ext in [".js",".json",".map",".config",".env",".lock"]):
        score += 2
    if "?" in url:
        score += 1
    return score

# ---------- Analysis ----------
def analyze_text(url, text, headers):
    findings = []
    def add(kind, detail, evidence=None, severity_override=None):
        findings.append({
            "type": kind,
            "url": url,
            "detail": detail,
            "evidence": (evidence or "")[:400],
            "severity": SEVERITY.get(kind, 5) if severity_override is None else severity_override,
            "timestamp": time.time()
        })

    if not text:
        return findings

    if AWS_ACCESS.search(text) or GCP_KEY.search(text) or GENERIC_APIKEY.search(text) or JWT_RE.search(text):
        m = JWT_RE.search(text)
        add("JWT / API Keys", "Token/API key pattern found", (m.group(0) if m else "key"), severity_override=SEVERITY["JWT / API Keys"])

    if re.search(r"(?i)(username|password|passwd|pwd).{0,40}[:=]\s*['\"]", text):
        add("Hardcoded Credentials", "Possible hardcoded credentials pattern", severity_override=SEVERITY["Hardcoded Credentials"])

    if CONFIG_KEYS.search(text):
        add("Sensitive Info Leak", "Config/Env like strings in source")

    emails = set(EMAIL_RE.findall(text))
    if emails:
        add("Sensitive Info Leak", f"Emails exposed: {', '.join(list(emails)[:5])}", ", ".join(list(emails)[:3]))

    if WS_RE.search(text):
        add("WebSocket Endpoint", "WebSocket URL found in asset", WS_RE.search(text).group(0))

    if OPEN_REDIRECT_KEYS.search(text):
        add("Open Redirect (param)", "Redirect-like parameter mentioned in source")

    if UPLOAD_HINT.search(text):
        add("Upload Endpoint (potential)", "Upload related hints")

    if RFI_RCE_HINT.search(text):
        add("RFI/RCE Hint", "Possible server-side exec/child_process references", severity_override=SEVERITY["RFI/RCE Hint"])

    if DOM_XSS_SINKS.search(text):
        add("DOM XSS Sink", "Potential DOM sink found (innerHTML/document.write/eval)")

    if ID_PARAM.search(text) or NUM_IN_URL.search(url):
        add("IDOR Candidate", "ID-like parameter or numeric path detected")

    for rx,msg in OUTDATED_LIBS:
        if rx.search(text) or rx.search(url):
            add("Outdated Library (CVE-prone)", msg)

    if '"dependencies"' in text or '"devDependencies"' in text:
        add("Dependency/Package Disclosure", "package.json-like content visible")

    embedded = [m for m in URL_IN_TEXT.findall(text) if not m.endswith((".png",".jpg",".jpeg",".gif",".svg"))]
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
            if path.startswith("/.env") or path.endswith(".config") or path.endswith(".json"):
                results.append({"type":"Config/Env Disclosure","url":url,"detail":f"{path} accessible (HTTP {code})","evidence":(text[:300] if text else ""), "severity":SEVERITY["Config/Env Disclosure"], "timestamp":time.time()})
            elif path in ("/admin","/administrator","/login","/auth","/hidden","/secret"):
                results.append({"type":"Hidden Login/Portal","url":url,"detail":f"Portal path accessible (HTTP {code})","evidence":"", "severity":SEVERITY["Hidden Login/Portal"], "timestamp":time.time()})
            elif path == "/package.json":
                results.append({"type":"Dependency/Package Disclosure","url":url,"detail":"package.json readable","evidence":(text[:300] if text else ""), "severity":SEVERITY["Dependency/Package Disclosure"], "timestamp":time.time()})
            else:
                results.append({"type":"Service/Endpoint Map","url":url,"detail":f"{path} accessible (HTTP {code})","evidence":(text[:200] if text else ""), "severity":SEVERITY["Service/Endpoint Map"], "timestamp":time.time()})
        elif code in (401,403):
            if path in ("/admin","/administrator"):
                results.append({"type":"Hidden Login/Portal","url":url,"detail":f"{path} present but protected (HTTP {code})","evidence":"", "severity":SEVERITY["Hidden Login/Portal"], "timestamp":time.time()})
    return results

# ---------- Version detection ----------
def detect_versions_from_headers(headers):
    vers = []
    srv = headers.get("Server")
    xp = headers.get("X-Powered-By") or headers.get("X-Powered-By".lower())
    if srv:
        vers.append(("Server", srv))
    if xp:
        vers.append(("X-Powered-By", xp))
    return vers

def detect_versions_from_text(url, text):
    found = []
    if not text:
        return found
    # WordPress meta generator
    m = re.search(r'<meta name=["\']?generator["\']? content=["\']?WordPress\s*([^"\']+)["\']?>', text, re.I)
    if m:
        found.append(("WordPress", m.group(1)))
    # package.json content
    if '"name"' in text and '"version"' in text:
        # try to parse JSON safely snippet
        try:
            j = json.loads(text)
            if isinstance(j, dict):
                name = j.get("name")
                ver = j.get("version")
                if name and ver:
                    found.append((name, ver))
        except Exception:
            pass
    # simple regex for postgres/mysql in footer or comments
    m2 = re.search(r"(postgresql|postgres)[^\d]*([\d\.]+)", text, re.I)
    if m2:
        found.append((m2.group(1), m2.group(2)))
    return found

# ---------- CVE / ExploitDB checks ----------
def query_nvd(product, version):
    # Use NVD v2 search by keyword (product + version)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    q = f"{product} {version}"
    try:
        r = requests.get(base, params={"keywordSearch": q}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = []
            if isinstance(data, dict) and data.get("vulnerabilities"):
                for v in data["vulnerabilities"][:20]:
                    try:
                        cveid = v.get("cve", {}).get("id")
                        if cveid:
                            vulns.append(cveid)
                    except:
                        continue
            return vulns
    except Exception:
        return []
    return []

def query_exploitdb(product, version):
    # A lightweight scrape of exploit-db search results (best-effort)
    # We'll search by product name; exploit-db search page: https://www.exploit-db.com/search?q=...
    base = "https://www.exploit-db.com/search"
    try:
        r = requests.get(base, params={"q": f"{product} {version}"}, timeout=15, headers=HEADERS)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            results = []
            # exploit-db lists results in table rows; find anchors with /exploits/
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/exploits/"):
                    title = a.get_text(strip=True)
                    results.append({"href":"https://www.exploit-db.com"+href, "title": title})
            return results[:20]
    except Exception:
        return []
    return []

# ---------- Main scan for a single base URL ----------
def scan_base(base_url, do_cves=False):
    base_url = norm_url(base_url)
    findings = []
    versions = []
    start = time.time()

    text, headers = fetch_text(base_url)
    if text:
        findings += analyze_text(base_url, text, headers or {})
        # collect versions from page
        versions += detect_versions_from_text(base_url, text)
    if headers:
        versions += detect_versions_from_headers(headers)

    # assets
    assets = set()
    if text:
        for a in extract_assets(base_url, text):
            assets.add(a)
    for g in guess_more_assets(base_url):
        assets.add(g)

    # fetch assets in parallel
    def fetchan(u):
        t,h = fetch_text(u)
        res = []
        if t:
            res = analyze_text(u, t, h or {})
            res_versions = detect_versions_from_text(u, t)
            return res, res_versions
        return [], []

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetchan, u): u for u in assets}
        for fut in as_completed(futures):
            try:
                res, resv = fut.result()
                if res:
                    findings.extend(res)
                if resv:
                    versions.extend(resv)
            except Exception:
                continue

    # sensitive paths
    findings.extend(check_sensitive_paths(base_url))

    # attach timestamps to findings if missing
    now = time.time()
    for f in findings:
        if "timestamp" not in f:
            f["timestamp"] = now

    duration = time.time() - start

    # Versions unique filter
    unique_versions = {}
    for (name, ver) in versions:
        if not name: continue
        key = name.lower()
        if key not in unique_versions:
            unique_versions[key] = ver

    cve_results = {}
    exploit_results = {}

    if do_cves and unique_versions:
        # Query NVD & ExploitDB (respect rate)
        for name, ver in unique_versions.items():
            time.sleep(CVE_QUERY_PAUSE)
            nvd = query_nvd(name, ver)
            if nvd:
                cve_results[f"{name} {ver}"] = nvd
                # add findings for each CVE (summary-level)
                findings.append({"type":"CVE Match","url":base_url,"detail":f"{name} {ver} -> CVEs: {', '.join(nvd[:5])}","evidence":"","severity":SEVERITY.get("CVE Match",10),"timestamp":time.time()})
            time.sleep(EXPLOITDB_QUERY_PAUSE)
            edb = query_exploitdb(name, ver)
            if edb:
                exploit_results[f"{name} {ver}"] = edb
                findings.append({"type":"ExploitDB Match","url":base_url,"detail":f"{name} {ver} -> {len(edb)} exploit-db results","evidence":json.dumps(edb[:5]),"severity":SEVERITY.get("ExploitDB Match",9),"timestamp":time.time()})

    meta = {
        "base": base_url,
        "scan_time_sec": round(duration,2),
        "timestamp": time.time(),
        "versions": unique_versions
    }

    return findings, meta, cve_results, exploit_results

# ---------- Reports save ----------
def save_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity","type","url","detail","evidence","timestamp"])
        for it in findings:
            w.writerow([it.get("severity",5), it.get("type",""), it.get("url",""), it.get("detail",""), it.get("evidence",""), it.get("timestamp","")])

def save_html(findings, path):
    rows = []
    for it in findings:
        ts = it.get("timestamp")
        ts_str = datetime.datetime.fromtimestamp(ts).isoformat() if ts else ""
        rows.append(f"<tr><td>{it.get('severity',5)}</td><td>{it.get('type','')}</td><td>{it.get('url','')}</td><td>{it.get('detail','')}</td><td><pre style='white-space:pre-wrap'>{(it.get('evidence','') or '')}</pre></td><td>{ts_str}</td></tr>")
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>GoldMine Advanced Report</title>
    <style>body{{font-family:system-ui,Arial}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px}}th{{background:#f4f4f4}}</style></head><body>
    <h1>GoldMine Advanced Scan Report</h1>
    <p>Non-intrusive heuristics. Confirm findings manually.</p>
    <table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Evidence</th><th>Timestamp</th></tr></thead><tbody>
    {''.join(rows) if rows else '<tr><td colspan=6>No findings</td></tr>'}
    </tbody></table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_summary(findings, metas, seed_hosts, start_ts, end_ts, outdir):
    duration = end_ts - start_ts
    total = len(findings)
    # aggregate by hostname but only include hostnames belonging to seed hosts (include subdomains)
    host_counts = Counter()
    path_counts = Counter()
    type_counts = Counter()
    param_hits = Counter()
    version_map = {}
    for it in findings:
        url = it.get("url","")
        p = urlparse(url)
        host = p.hostname or ""
        path = p.path or "/"
        # check membership: host endswith any seed_host
        include = False
        for sh in seed_hosts:
            if host == sh or host.endswith("."+sh):
                include = True
                break
        if include:
            host_counts[host]+=1
            path_counts[path]+=1
            type_counts[it.get("type","")] += 1
            # param heuristics
            txt = (it.get("detail","")+" "+it.get("evidence","")).lower()
            for key in ["redirect","next","return","token","id","user_id","order_id","session","auth","api_key","secret"]:
                if key in txt:
                    param_hits[key]+=1
    # versions aggregation from metas
    for m in metas:
        for k,v in (m.get("versions") or {}).items():
            version_map[k]=v

    # write
    summary_file = os.path.join(outdir, "report_summary.txt")
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("GoldMine Advanced Scan Summary\n")
        f.write("=============================\n")
        f.write(f"Start: {datetime.datetime.fromtimestamp(start_ts).isoformat()}\n")
        f.write(f"End:   {datetime.datetime.fromtimestamp(end_ts).isoformat()}\n")
        f.write(f"Duration (s): {duration:.2f}\n")
        f.write(f"Total findings: {total}\n\n")
        f.write("Top vulnerable hosts (seed-limited):\n")
        for h,c in host_counts.most_common(30):
            f.write(f"  {h} : {c}\n")
        f.write("\nTop vulnerable paths:\n")
        for p,c in path_counts.most_common(30):
            f.write(f"  {p} : {c}\n")
        f.write("\nFindings by type:\n")
        for t,c in type_counts.most_common(40):
            f.write(f"  {t} : {c}\n")
        f.write("\nTop risky parameter keywords:\n")
        for k,c in param_hits.most_common(40):
            f.write(f"  {k} : {c}\n")
        f.write("\nDetected versions (sample):\n")
        for k,v in version_map.items():
            f.write(f"  {k} : {v}\n")
    return summary_file

# ---------- Ctrl+C graceful handler ----------
global_state = {
    "findings": [],
    "metas": [],
    "start_ts": None,
    "end_ts": None,
    "outdir": DEFAULT_OUT,
    "seed_hosts": []
}

def save_and_exit(signum=None, frame=None):
    gs = global_state
    gs["end_ts"] = time.time()
    print("\n[!] Saving reports (Ctrl+C or exit)...")
    all_findings = gs["findings"]
    all_metas = gs["metas"]
    outdir = gs["outdir"]
    os.makedirs(outdir, exist_ok=True)
    # sort
    all_findings.sort(key=lambda x: x.get("severity",5), reverse=True)
    save_csv(all_findings, os.path.join(outdir, "report.csv"))
    save_html(all_findings, os.path.join(outdir, "report.html"))
    save_json(all_findings, os.path.join(outdir, "report.json"))
    save_json(all_metas, os.path.join(outdir, "report_metas.json"))
    # summary
    summary = generate_summary(all_findings, all_metas, gs["seed_hosts"], gs["start_ts"] or gs["end_ts"], gs["end_ts"], outdir)
    # versions
    vrfile = os.path.join(outdir, "versions_report.txt")
    with open(vrfile, "w", encoding="utf-8") as f:
        for m in all_metas:
            if m.get("versions"):
                f.write(f"{m.get('base')} -> {json.dumps(m.get('versions'))}\n")
    # CVE/Exploit results
    save_json(gs.get("cve_results", {}), os.path.join(outdir, "cve_report.json"))
    save_json(gs.get("exploit_results", {}), os.path.join(outdir, "exploitdb_report.json"))
    print(f"[+] Reports saved to {outdir} (report.csv, report.html, report.json, report_summary.txt, versions_report.txt, cve_report.json, exploitdb_report.json)")
    sys.exit(0)

signal.signal(signal.SIGINT, save_and_exit)

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="GoldMine Advanced Scanner (passive) with CVE/ExploitDB checks")
    p.add_argument("urls", help="File with seed URLs (one per line)")
    p.add_argument("--out", "-o", default=DEFAULT_OUT, help="Output folder")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Thread workers")
    p.add_argument("--depth", "-d", type=int, default=1, help="Depth (for guessed assets; not full crawler depth)")
    p.add_argument("--check-cves", action="store_true", help="Query NVD and exploit-db for discovered versions (slower)")
    return p.parse_args()

# ---------- Main runner ----------
def main():
    args = parse_args()
    seeds = []
    with open(args.urls, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                seeds.append(norm_url(ln))
    if not seeds:
        print("No seeds provided.")
        return
    os.makedirs(args.out, exist_ok=True)
    global_state["outdir"] = args.out
    # seed hosts (for aggregation): hostnames from seeds (no scheme)
    seed_hosts = []
    for s in seeds:
        h = urlparse(s).hostname
        if h:
            seed_hosts.append(h)
    global_state["seed_hosts"] = seed_hosts

    # progress bar over seeds
    results = []
    metas = []
    cve_all = {}
    exploit_all = {}
    global_state["findings"] = []
    global_state["metas"] = []
    global_state["start_ts"] = time.time()

    print(f"[+] Starting scan of {len(seeds)} seeds with {args.workers} workers. Output: {args.out}")
    pbar = tqdm(total=len(seeds), desc="Seeds", unit="site")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_map = {ex.submit(scan_base, s, args.check_cves): s for s in seeds}
        for fut in as_completed(future_map):
            s = future_map[fut]
            try:
                findings, meta, cves, edb = fut.result()
                # collect
                if findings:
                    global_state["findings"].extend(findings)
                global_state["metas"].append(meta)
                # merge cves/exploits
                for k,v in cves.items(): cve_all[k]=v
                for k,v in edb.items(): exploit_all[k]=v
                pbar.update(1)
                pbar.set_postfix({"last": s, "findings": len(global_state["findings"])})
            except Exception as e:
                print(f"[x] Error scanning {s}: {e}")
                pbar.update(1)
    pbar.close()
    # store collected results
    global_state["cve_results"] = cve_all
    global_state["exploit_results"] = exploit_all
    global_state["end_ts"] = time.time()

    # final save
    save_and_exit()

if __name__ == "__main__":
    main()
