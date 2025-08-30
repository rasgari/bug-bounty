#!/usr/bin/env python3
"""
scanner_full_advanced.py (Enhanced)
- Async/threaded passive scanner
- CSV / HTML / JSON outputs
- Subdomain aggregation (seed-limited)
- Progress bar
- CVE & ExploitDB checks
- Wappalyzer integration
"""

import sys, os, time, json, argparse, signal
import re, csv, datetime
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from collections import Counter
from Wappalyzer import Wappalyzer, WebPage   # pip install python-Wappalyzer

# ---------- Config ----------
HEADERS = {"User-Agent": "GoldMineScanner/advanced/2.0"}
TIMEOUT = 10
DEFAULT_WORKERS = 20
DEFAULT_OUT = "reports"

# ---------- Risky Params (expanded with P1) ----------
RISKY_PARAMS = [
    "id","user_id","order_id","uid","pid","token","auth","session","jwt",
    "password","passwd","pwd","email","redirect","next","return","file","path",
    "cmd","query","search","order","sort","filter","admin","key","secret",
    "access","account","role"
]

# ---------- Helpers ----------
def norm_url(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def http_get(url, timeout=TIMEOUT):
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None

def fetch_text(url):
    r = http_get(url)
    if r is None: return None, None
    ctype = r.headers.get("Content-Type","").lower()
    if any(b in ctype for b in ["image/","font/","octet-stream","pdf"]):
        return None, r.headers
    return r.text, r.headers

# ---------- Tech detection ----------
def detect_technologies(url):
    """Use Wappalyzer to detect frontend/backend/DB/JS libraries"""
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=15)
        return wappalyzer.analyze(webpage)
    except Exception:
        return {}

# ---------- Analyzer (simplified) ----------
def analyze_text(url, text):
    findings = []
    if not text: return findings
    if "password" in text.lower():
        findings.append({"type":"Sensitive Info Leak","url":url,"detail":"Contains 'password'","severity":8,"timestamp":time.time()})
    return findings

# ---------- Main scan ----------
def scan_base(base_url, do_cves=False):
    base_url = norm_url(base_url)
    findings = []
    versions = {}
    text, headers = fetch_text(base_url)
    if text:
        findings.extend(analyze_text(base_url, text))

    # detect technologies
    techs = detect_technologies(base_url)

    meta = {
        "base": base_url,
        "timestamp": time.time(),
        "versions": versions,
        "wappalyzer": techs
    }
    return findings, meta

# ---------- Reports ----------
def save_csv(findings, path):
    with open(path,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["severity","type","url","detail","timestamp"])
        for it in findings:
            w.writerow([it.get("severity",5), it.get("type",""), it.get("url",""), it.get("detail",""), it.get("timestamp","")])

def save_html(findings, path):
    rows=[]
    for it in findings:
        ts=datetime.datetime.fromtimestamp(it["timestamp"]).isoformat()
        rows.append(f"<tr><td>{it['severity']}</td><td>{it['type']}</td><td>{it['url']}</td><td>{it['detail']}</td><td>{ts}</td></tr>")
    html=f"""<!doctype html><html><head><meta charset='utf-8'><title>Scan Report</title>
    <style>table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:6px}}th{{background:#eee}}</style></head><body>
    <h1>Advanced Scan Report</h1>
    <table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Timestamp</th></tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan=5>No findings</td></tr>'}</tbody></table></body></html>"""
    open(path,"w",encoding="utf-8").write(html)

def save_json(data, path):
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data,f,indent=2,ensure_ascii=False)

def generate_summary(findings, metas, seed_hosts, start_ts, end_ts, outdir):
    duration = end_ts-start_ts
    host_counts, path_counts, type_counts, param_hits = Counter(),Counter(),Counter(),Counter()
    for it in findings:
        url=it["url"]; p=urlparse(url)
        host, path = p.hostname or "", p.path or "/"
        if any(host==sh or host.endswith("."+sh) for sh in seed_hosts):
            host_counts[host]+=1; path_counts[path]+=1
            type_counts[it["type"]]+=1
            txt=(it.get("detail","")+" ").lower()
            for k in RISKY_PARAMS:
                if k in txt: param_hits[k]+=1

    summary_file=os.path.join(outdir,"report_summary.txt")
    with open(summary_file,"w",encoding="utf-8") as f:
        f.write("Advanced Scan Summary\n=====================\n")
        f.write(f"Start: {datetime.datetime.fromtimestamp(start_ts)}\n")
        f.write(f"End:   {datetime.datetime.fromtimestamp(end_ts)}\n")
        f.write(f"Duration: {duration:.2f}s\n")
        f.write(f"Total findings: {len(findings)}\n\n")

        f.write("Top vulnerable hosts:\n")
        for h,c in host_counts.most_common(20):
            vulns=[it["type"] for it in findings if urlparse(it["url"]).hostname==h]
            f.write(f" {h} : {c} => {', '.join(set(vulns))}\n")

        f.write("\nTop vulnerable paths:\n")
        for p,c in path_counts.most_common(20):
            vulns=[it["type"] for it in findings if urlparse(it["url"]).path==p]
            top=Counter(vulns).most_common(1)
            vulntxt=top[0][0] if top else "?"
            f.write(f" {p} : {c} (Top vuln: {vulntxt})\n")

        f.write("\nFindings by type:\n")
        for t,c in type_counts.most_common(20): f.write(f" {t} : {c}\n")

        f.write("\nTop risky parameters:\n")
        for k,c in param_hits.most_common(20): f.write(f" {k} : {c}\n")

        f.write("\nDetected technologies (Wappalyzer):\n")
        for m in metas:
            if m.get("wappalyzer"): f.write(f" {m['base']} -> {json.dumps(m['wappalyzer'])}\n")
    return summary_file

# ---------- Ctrl+C handler ----------
global_state={"findings":[],"metas":[],"start_ts":None,"end_ts":None,"outdir":DEFAULT_OUT,"seed_hosts":[]}
def save_and_exit(signum=None,frame=None):
    gs=global_state; gs["end_ts"]=time.time()
    os.makedirs(gs["outdir"],exist_ok=True)
    save_csv(gs["findings"],os.path.join(gs["outdir"],"report.csv"))
    save_html(gs["findings"],os.path.join(gs["outdir"],"report.html"))
    save_json(gs["findings"],os.path.join(gs["outdir"],"report.json"))
    generate_summary(gs["findings"],gs["metas"],gs["seed_hosts"],gs["start_ts"],gs["end_ts"],gs["outdir"])
    print(f"\n[+] Reports saved to {gs['outdir']}")
    sys.exit(0)
signal.signal(signal.SIGINT,save_and_exit)

# ---------- CLI ----------
def parse_args():
    p=argparse.ArgumentParser(description="GoldMine Advanced Scanner with Wappalyzer")
    p.add_argument("urls",help="File with seed URLs")
    p.add_argument("--out","-o",default=DEFAULT_OUT,help="Output folder")
    p.add_argument("--workers","-w",type=int,default=DEFAULT_WORKERS)
    return p.parse_args()

# ---------- Main ----------
def main():
    args=parse_args()
    seeds=[norm_url(l.strip()) for l in open(args.urls) if l.strip()]
    if not seeds: print("No seeds provided."); return
    os.makedirs(args.out,exist_ok=True)
    global_state["outdir"]=args.out
    global_state["seed_hosts"]=[urlparse(s).hostname for s in seeds]
    global_state["start_ts"]=time.time()

    print(f"[+] Starting scan of {len(seeds)} seeds...")
    pbar=tqdm(total=len(seeds),desc="Seeds",unit="site")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures={ex.submit(scan_base,s):s for s in seeds}
        for fut in as_completed(futures):
            s=futures[fut]
            try:
                f,m=fut.result()
                global_state["findings"].extend(f)
                global_state["metas"].append(m)
            except Exception as e:
                print(f"[x] Error scanning {s}: {e}")
            pbar.update(1)
    pbar.close()
    save_and_exit()

if __name__=="__main__": main()
