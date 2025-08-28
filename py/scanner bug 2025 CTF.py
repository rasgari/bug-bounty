#!/usr/bin/env python3
"""
crawler_scanner.py
Async deep crawler + heuristic passive scanner for Bug Bounty / CTF usage.

Features:
 - Async crawler using aiohttp
 - Depth-limited crawl, domain-restricted (with include-subdomains option)
 - Heuristic passive checks on pages and assets (JS/JSON/etc.)
 - SQLite state to resume and avoid reprocessing
 - Prioritization of "gold" assets (main, bundle, config, auth, api, session, etc.)
 - Profiles: ctf (fast/shallow) and bounty (thorough/deeper)
 - Outputs: report.csv and report.html sorted by severity
"""

import asyncio
import argparse
import aiosqlite
import aiohttp
from aiohttp import ClientConnectorError, ClientResponseError, ClientOSError, ServerTimeoutError
from yarl import URL
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import csv
import time
import os
from collections import defaultdict

# -----------------------
# Configuration / Regex
# -----------------------
HEADERS = {"User-Agent": "AsyncGoldCrawler/1.0 (+passive)"}
TIMEOUT = 12
DEFAULT_DB = "crawler_state.db"
REPORT_CSV = "report.csv"
REPORT_HTML = "report.html"

GOLD_KEYWORDS = set([
    "main","app","runtime","bundle","polyfills","auth","config",
    "settings","local","dev","data","api","session","user",
    "core","client","server","utils","base"
])

# Regex patterns for heuristics (non-intrusive)
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.]{10,}")
APIKEY_GENERIC = re.compile(r"(?i)(api[_-]?key|token|secret|access[_-]?key|client[_-]?secret)[\"'\s:=]{0,4}([A-Za-z0-9\-_]{16,})")
AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOM_XSS_SINKS = re.compile(r"(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\()")
OPEN_REDIRECT_KEYS = re.compile(r"(?i)(redirect|next|return|url|dest|destination)")
ID_PARAM = re.compile(r"(?i)\b(id|user_id|order_id|uid|pid)\b")
NUM_IN_URL = re.compile(r"/\d{1,12}(/|$)")
UPLOAD_HINT = re.compile(r"(?i)(upload|multipart/form-data|file\s*:)")
RFI_HINT = re.compile(r"(?i)(exec\(|child_process|spawn\(|system\()")
AUTH_BYPASS_HINT = re.compile(r"(?i)(isAuthenticated\s*:\s*false|bypassAuth|allowAnonymous)")

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/config.json", "/settings.json", "/package.json",
    "/.git/config", "/.htpasswd", "/wp-config.php", "/xmlrpc.php",
    "/admin", "/administrator", "/login", "/auth", "/.well-known"
]

SEVERITY_MAP = {
    "Config/Env Disclosure": 10,
    "JWT / API Keys": 10,
    "Hardcoded Credentials": 9,
    "Sensitive Info Leak": 9,
    "Hidden Login/Portal": 8,
    "Open Redirect (param)": 8,
    "Upload Endpoint (potential)": 7,
    "RFI/RCE Hint": 9,
    "DOM XSS Sink": 8,
    "IDOR Candidate": 7,
    "WebSocket Endpoint": 6,
    "Dependency/Package Disclosure": 6,
    "Service/Endpoint Map": 5,
    "Outdated Library": 5,
    "Multi Indicator": 4
}

# -----------------------
# Utilities
# -----------------------
def normalize_url(u):
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def same_domain(u, base, include_subdomains=False):
    pu = urlparse(u).hostname or ""
    pb = urlparse(base).hostname or ""
    if not pu or not pb:
        return False
    if pu == pb:
        return True
    if include_subdomains and pu.endswith("." + pb):
        return True
    return False

def prioritize_asset(url):
    low = 0
    for k in GOLD_KEYWORDS:
        if k in url.lower():
            low += 1
    # static file types get extra score
    if any(url.lower().endswith(ext) for ext in [".js",".json",".map",".config",".env",".lock"]):
        low += 2
    return low

# -----------------------
# SQLite state management
# -----------------------
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS frontier (
    url TEXT PRIMARY KEY,
    base TEXT,
    depth INTEGER,
    status TEXT,
    priority INTEGER,
    added_at REAL
);
CREATE TABLE IF NOT EXISTS visited (
    url TEXT PRIMARY KEY,
    base TEXT,
    depth INTEGER,
    fetched_at REAL,
    http_code INTEGER,
    content_type TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    base TEXT,
    finding_type TEXT,
    detail TEXT,
    evidence TEXT,
    severity INTEGER,
    created_at REAL
);
"""

# -----------------------
# Scanner heuristics
# -----------------------
def analyze_text(url, text, headers):
    findings = []
    def add(t, d, e=None):
        sev = SEVERITY_MAP.get(t, 4)
        findings.append({"url": url, "type": t, "detail": d, "evidence": (e or "")[:400], "severity": sev})
    if not text:
        return findings

    # tokens / keys
    if JWT_RE.search(text) or APIKEY_GENERIC.search(text) or AWS_ACCESS.search(text) or GCP_KEY.search(text):
        add("JWT / API Keys", "Possible token/key pattern found", JWT_RE.search(text).group(0) if JWT_RE.search(text) else (APIKEY_GENERIC.search(text).group(0) if APIKEY_GENERIC.search(text) else "key"))
    # emails
    emails = set(EMAIL_RE.findall(text))
    if emails:
        add("Sensitive Info Leak", f"Emails exposed: {', '.join(list(emails)[:5])}", ", ".join(list(emails)[:3]))
    # DOM XSS sinks
    if DOM_XSS_SINKS.search(text):
        add("DOM XSS Sink", "Potential DOM sink (innerHTML/document.write/eval) found")
    # Open redirect params
    if OPEN_REDIRECT_KEYS.search(text):
        add("Open Redirect (param)", "Redirect-like parameter names present in asset or page")
    # upload hints
    if UPLOAD_HINT.search(text):
        add("Upload Endpoint (potential)", "Upload or multipart hints present")
    # RFI/RCE hints
    if RFI_HINT.search(text):
        add("RFI/RCE Hint", "Server-side exec/child_process keywords found in JS/text")
    # auth bypass hints
    if AUTH_BYPASS_HINT.search(text):
        add("Authentication Bypass Hint", "Possible bypass flags in client code")
    # idor / numeric ids
    if ID_PARAM.search(text) or NUM_IN_URL.search(url):
        add("IDOR Candidate", "ID-like parameters or numeric path detected")
    # package.json / dependency leak
    if '"dependencies"' in text or '"devDependencies"' in text or 'package.json' in url:
        add("Dependency/Package Disclosure", "package.json style content or dependency listing")
    # websocket endpoints
    ws = re.findall(r"\b(wss?:\/\/[^\s\"'<>]+)", text)
    if ws:
        add("WebSocket Endpoint", f"Found {len(ws)} websocket endpoints", ws[0])
    return findings

# -----------------------
# Async fetch + parse
# -----------------------
class CrawlerScanner:
    def __init__(self, db_path=DEFAULT_DB, timeout=TIMEOUT, concurrency=10, depth_limit=2, include_subdomains=False, profile="ctf"):
        self.db_path = db_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.depth_limit = depth_limit
        self.include_subdomains = include_subdomains
        self.profile = profile
        self.sem = asyncio.Semaphore(concurrency)
        self.session = None
        self.base_start = []  # list of seeds

    async def init_db(self):
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.executescript(CREATE_TABLES_SQL)
        await self.db.commit()

    async def close_db(self):
        await self.db.close()

    async def add_frontier(self, url, base, depth, priority=0):
        try:
            await self.db.execute("INSERT OR IGNORE INTO frontier(url,base,depth,status,priority,added_at) VALUES(?,?,?,?,?,?)",
                                  (url, base, depth, "queued", priority, time.time()))
            await self.db.commit()
        except Exception:
            pass

    async def pop_frontier(self):
        async with self.db.execute("SELECT url, base, depth FROM frontier WHERE status='queued' ORDER BY priority DESC, added_at ASC LIMIT 1") as cur:
            row = await cur.fetchone()
            if not row:
                return None
            url, base, depth = row
            await self.db.execute("UPDATE frontier SET status='in-progress' WHERE url=?", (url,))
            await self.db.commit()
            return url, base, depth

    async def mark_visited(self, url, base, depth, code, ctype):
        await self.db.execute("INSERT OR REPLACE INTO visited(url,base,depth,fetched_at,http_code,content_type) VALUES(?,?,?,?,?,?)",
                              (url, base, depth, time.time(), code, ctype))
        await self.db.execute("DELETE FROM frontier WHERE url=?", (url,))
        await self.db.commit()

    async def save_finding(self, base, item):
        await self.db.execute("INSERT INTO findings(url,base,finding_type,detail,evidence,severity,created_at) VALUES(?,?,?,?,?,?,?)",
                              (item["url"], base, item["type"], item["detail"], item.get("evidence",""), item["severity"], time.time()))
        await self.db.commit()

    async def enqueue_seed(self, seed):
        base = seed
        self.base_start.append(base)
        await self.add_frontier(seed, base, 0, priority=prioritize_asset(seed))

    async def extract_links(self, base, text, current_depth):
        out = set()
        soup = BeautifulSoup(text, "html.parser")
        # a, link, script, img, source
        for tag in soup.find_all(["a","link","script","img","source","iframe"]):
            src = tag.get("href") or tag.get("src") or tag.get("data-src")
            if not src: continue
            # ignore mailto:/tel:
            if src.startswith("mailto:") or src.startswith("tel:"): continue
            full = urljoin(base, src)
            out.add(full)
        # also find URLs in JS/text
        for m in re.findall(r"https?://[^\s'\"()<>]+", text):
            out.add(m)
        # include guessed assets for depth=0 (common JS paths)
        if current_depth == 0:
            for candidate in ["/main.js","/app.js","/runtime.js","/bundle.js","/config.json","/settings.json","/manifest.json","/sw.js","/package.json"]:
                out.add(urljoin(base, candidate))
        return out

    async def fetch(self, url):
        try:
            async with self.sem:
                async with self.session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                    text = await resp.text(errors="ignore")
                    return resp.status, resp.headers, text
        except (ClientConnectorError, ClientResponseError, ClientOSError, asyncio.TimeoutError, ServerTimeoutError):
            return None, None, None
        except Exception:
            return None, None, None

    async def worker_loop(self):
        while True:
            item = await self.pop_frontier()
            if not item:
                await asyncio.sleep(0.2)
                # check if frontier empty
                async with self.db.execute("SELECT COUNT(*) FROM frontier WHERE status='queued'") as cur:
                    row = await cur.fetchone()
                    if row and row[0] == 0:
                        return
                continue
            url, base, depth = item
            # scope check
            if not same_domain(url, base, include_subdomains=self.include_subdomains):
                # drop or skip external
                await self.db.execute("DELETE FROM frontier WHERE url=?", (url,))
                await self.db.commit()
                continue
            # fetch
            status, headers, text = await self.fetch(url)
            ctype = headers.get("Content-Type","") if headers else ""
            await self.mark_visited(url, base, depth, status or 0, ctype or "")
            if not text:
                continue
            # analyze content
            findings = analyze_text(url, text, headers or {})
            for f in findings:
                await self.save_finding(base, f)
            # extract links and enqueue (if depth allows)
            if depth < self.depth_limit:
                links = await self.extract_links(url, text, depth)
                for l in links:
                    if not same_domain(l, base, include_subdomains=self.include_subdomains):
                        continue
                    # priority compute
                    prio = prioritize_asset(l)
                    # small heuristic: if link contains query or looks like asset, raise prio
                    if "?" in l:
                        prio += 1
                    if any(l.lower().endswith(ext) for ext in [".js",".json",".map",".config"]):
                        prio += 2
                    await self.add_frontier(l, base, depth+1, prio)

    async def run(self, seeds, workers=10):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
            self.session = session
            # ensure db
            await self.init_db()
            # enqueue seeds
            for s in seeds:
                await self.enqueue_seed(s)
            # spawn workers
            tasks = [asyncio.create_task(self.worker_loop()) for _ in range(workers)]
            await asyncio.gather(*tasks)
            await self.close_db()

# -----------------------
# Reporting / Export
# -----------------------
async def export_reports(db_path=DEFAULT_DB, csv_path=REPORT_CSV, html_path=REPORT_HTML):
    conn = await aiosqlite.connect(db_path)
    rows = []
    async with conn.execute("SELECT url,base,finding_type,detail,evidence,severity,created_at FROM findings ORDER BY severity DESC, created_at ASC") as cur:
        async for r in cur:
            rows.append(r)
    await conn.close()
    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["severity","finding_type","url","base","detail","evidence","timestamp"])
        for r in rows:
            writer.writerow([r[5], r[2], r[0], r[1], (r[3] or ""), (r[4] or ""), r[6]])
    # HTML
    html_rows = []
    for r in rows:
        sev = r[5] or 5
        html_rows.append(f"<tr><td>{sev}</td><td>{r[2]}</td><td>{r[0]}</td><td>{r[3] or ''}</td><td><pre style='white-space:pre-wrap'>{(r[4] or '')}</pre></td></tr>")
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Scan Report</title>
    <style>body{{font-family:system-ui,Arial}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px}}th{{background:#f4f4f4}}</style></head><body>
    <h1>Async Crawler Scanner Report</h1>
    <p>Non-intrusive findings ordered by severity (higher first)</p>
    <table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Detail</th><th>Evidence</th></tr></thead><tbody>
    {''.join(html_rows) if html_rows else '<tr><td colspan=5>No findings</td></tr>'}
    </tbody></table></body></html>"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

# -----------------------
# CLI and Orchestration
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Async deep crawler + passive scanner for CTF/bug bounty")
    p.add_argument("--input", "-i", required=True, help="File with seed URLs (one per line)")
    p.add_argument("--depth", type=int, default=1, help="Depth limit for crawling (CTF:1-2, Bounty:2-3)")
    p.add_argument("--workers", type=int, default=20, help="Concurrency (aiohttp clients)")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite DB path")
    p.add_argument("--profile", choices=["ctf","bounty"], default="ctf", help="Profile: ctf or bounty")
    p.add_argument("--include-subdomains", action="store_true", help="Follow subdomains of each seed")
    return p.parse_args()

def load_seeds(path):
    with open(path, "r", encoding="utf-8") as f:
        return [normalize_url(l.strip()) for l in f if l.strip()]

async def main_async(args):
    seeds = load_seeds(args.input)
    # set defaults by profile
    if args.profile == "ctf":
        depth = args.depth if args.depth else 1
        workers = args.workers if args.workers else 40
    else:
        depth = args.depth if args.depth else 3
        workers = args.workers if args.workers else 12

    cs = CrawlerScanner(db_path=args.db, timeout=TIMEOUT, concurrency=workers, depth_limit=depth, include_subdomains=args.include_subdomains, profile=args.profile)
    print(f"[+] Starting scan. seeds={len(seeds)} profile={args.profile} depth={depth} workers={workers}")
    await cs.run(seeds, workers=workers)
    print("[+] Crawl complete. Exporting reports...")
    await export_reports(db_path=args.db)
    print(f"[+] Reports generated: {REPORT_CSV}, {REPORT_HTML}")

def main():
    args = parse_args()
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
