#!/usr/bin/env python3
"""
google_dork_runner.py

دو حالت:
 1) generate-only: فقط یک لیست از دُرک‌ها برای دامنه تولید می‌کند و در فایل ذخیره می‌کند.
 2) run (google/bing): هر دُرک را با Google Custom Search API یا Bing Web Search API اجرا کرده
    و نتایج را به JSON و CSV خروجی می‌دهد.

پیش‌نیاز:
  - Python 3.7+
  - کتابخانه requests: pip install requests
  - برای Google: نیاز به GOOGLE_API_KEY و GOOGLE_CX (Custom Search Engine ID)
  - برای Bing (Azure): نیاز به BING_API_KEY و اختیاری BING_ENDPOINT (معمولاً https://api.bing.microsoft.com)

محل ذخیره خروجی:
  ./output/<domain>/dorks.txt
  ./output/<domain>/results.json
  ./output/<domain>/summary.csv

مثال‌ها:
  # فقط تولید دُرک‌ها
  python3 google_dork_runner.py --domain target.com --mode generate

  # اجرای روی Google CSE
  export GOOGLE_API_KEY=...
  export GOOGLE_CX=...
  python3 google_dork_runner.py --domain target.com --mode google --per-dork 3 --delay 1

  # اجرای روی Bing
  export BING_API_KEY=...
  python3 google_dork_runner.py --domain target.com --mode bing --per-dork 3 --delay 1
"""
import os
import sys
import time
import argparse
import requests
import json
import csv
from pathlib import Path
from urllib.parse import quote_plus

# -------------------------
# Default dorks templates
# -------------------------
DEFAULT_DORKS = [
    'site:{domain} inurl:admin OR inurl:login',
    'site:{domain} "index of" "backup"',
    'site:{domain} filetype:env OR filetype:ini "DB_PASSWORD" OR "DB_USER"',
    'site:{domain} filetype:sql "password" OR "credential"',
    'filetype:log intext:password site:{domain}',
    'site:{domain} inurl:wp-admin',
    'site:{domain} inurl:phpmyadmin',
    'site:{domain} inurl:config.php',
    'site:{domain} "index of" "dump"',
    'site:{domain} "DB_PASSWORD" OR "DB_USER" OR "aws_secret_access_key"'
]

# -------------------------
# Helpers
# -------------------------
def ensure_outdir(domain: str) -> Path:
    out = Path('output') / domain
    out.mkdir(parents=True, exist_ok=True)
    return out

def save_lines(path: Path, lines):
    path.write_text('\n'.join(lines), encoding='utf-8')
    print(f"[+] saved {len(lines)} lines to {path}")

# -------------------------
# Google Custom Search API
# -------------------------
def google_search(query: str, api_key: str, cx: str, num: int = 3):
    """
    Uses Google Custom Search JSON API.
    endpoint: https://www.googleapis.com/customsearch/v1
    params: key, cx, q, num (max 10)
    """
    endpoint = 'https://www.googleapis.com/customsearch/v1'
    params = {
        'key': api_key,
        'cx': cx,
        'q': query,
        'num': min(10, max(1, num))
    }
    r = requests.get(endpoint, params=params, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Google API error {r.status_code}: {r.text}")
    data = r.json()
    items = data.get('items', [])
    results = []
    for it in items[:num]:
        results.append({
            'title': it.get('title'),
            'link': it.get('link'),
            'snippet': it.get('snippet'),
            'displayLink': it.get('displayLink')
        })
    return results

# -------------------------
# Bing Web Search (Azure)
# -------------------------
def bing_search(query: str, api_key: str, endpoint: str = None, num: int = 3):
    """
    Uses Bing Web Search API (Azure).
    Default endpoint: https://api.bing.microsoft.com/v7.0/search
    Header: Ocp-Apim-Subscription-Key
    """
    if not endpoint:
        endpoint = 'https://api.bing.microsoft.com/v7.0/search'
    headers = {'Ocp-Apim-Subscription-Key': api_key}
    params = {'q': query, 'count': min(50, max(1, num))}
    r = requests.get(endpoint, headers=headers, params=params, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Bing API error {r.status_code}: {r.text}")
    js = r.json()
    results = []
    web_pages = js.get('webPages', {}).get('value', [])
    for it in web_pages[:num]:
        results.append({
            'title': it.get('name'),
            'link': it.get('url'),
            'snippet': it.get('snippet'),
            'displayLink': it.get('displayUrl')
        })
    return results

# -------------------------
# Main runner
# -------------------------
def run(domain: str, mode: str, per_dork: int, delay: float, dorks):
    outdir = ensure_outdir(domain)
    dork_lines = [d.format(domain=domain) for d in dorks]
    save_lines(outdir / 'dorks.txt', dork_lines)
    if mode == 'generate':
        print("[*] generate-only mode, done.")
        return

    results = []
    for idx, q in enumerate(dork_lines, start=1):
        print(f"[{idx}/{len(dork_lines)}] Query: {q}")
        try:
            if mode == 'google':
                api_key = os.getenv('GOOGLE_API_KEY')
                cx = os.getenv('GOOGLE_CX')
                if not api_key or not cx:
                    print("[!] GOOGLE_API_KEY and GOOGLE_CX env vars required for google mode.")
                    sys.exit(1)
                items = google_search(q, api_key, cx, num=per_dork)
            elif mode == 'bing':
                api_key = os.getenv('BING_API_KEY')
                endpoint = os.getenv('BING_ENDPOINT')  # optional
                if not api_key:
                    print("[!] BING_API_KEY env var required for bing mode.")
                    sys.exit(1)
                items = bing_search(q, api_key, endpoint, num=per_dork)
            else:
                raise ValueError("mode must be one of: generate, google, bing")
        except Exception as e:
            print("[!] Query failed:", e)
            items = []

        for it in items:
            results.append({
                'dork': q,
                'title': it.get('title'),
                'link': it.get('link'),
                'snippet': it.get('snippet'),
                'source': mode
            })
        # polite delay between queries
        time.sleep(delay)

    # save JSON
    out_json = outdir / 'results.json'
    out_json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"[+] saved results to {out_json} ({len(results)} items)")

    # save summary CSV
    out_csv = outdir / 'summary.csv'
    with out_csv.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=['dork', 'title', 'link', 'snippet', 'source'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"[+] saved CSV summary to {out_csv}")

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description='Generate or run Google dorks (generate / google / bing)')
    parser.add_argument('--domain', '-d', required=True, help='Target domain (e.g. example.com)')
    parser.add_argument('--mode', choices=['generate', 'google', 'bing'], default='generate',
                        help='generate: only produce dorks.txt; google: use Google CSE; bing: use Bing Web Search')
    parser.add_argument('--per-dork', type=int, default=3, help='number of results per dork to fetch')
    parser.add_argument('--delay', type=float, default=1.0, help='delay (seconds) between queries to avoid rate limits')
    parser.add_argument('--dork-file', help='optional path to a custom dork list (one per line)')
    args = parser.parse_args()

    if args.dork_file:
        p = Path(args.dork_file)
        if not p.exists():
            print("dork file not found:", p)
            sys.exit(1)
        dorks = [l.strip() for l in p.read_text(encoding='utf-8').splitlines() if l.strip() and not l.strip().startswith('#')]
    else:
        dorks = DEFAULT_DORKS

    # final run
    run(args.domain, args.mode, args.per_dork, args.delay, dorks)

if __name__ == '__main__':
    main()
