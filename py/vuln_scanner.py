import requests
import urllib.parse

xss_payload = "<script>alert(1)</script>"
redirect_payload = "https://google.com"
ssrf_payload = "http://127.0.0.1"
csrf_test_headers = {
    "Origin": "https://evil.com",
    "Referer": "https://evil.com"
}

output_file = "vuln_report.txt"
timeout = 6

def log_vuln(url, vuln_type, detail=""):
    with open(output_file, "a") as f:
        f.write(f"[{vuln_type}] {url} {detail}\n")

def test_xss(url):
    test_url = url + urllib.parse.quote(xss_payload)
    try:
        r = requests.get(test_url, timeout=timeout)
        if xss_payload.lower() in r.text.lower():
            log_vuln(test_url, "XSS")
    except:
        pass

def test_redirect(url):
    test_url = url + urllib.parse.quote(redirect_payload)
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=timeout)
        location = r.headers.get("Location", "")
        if redirect_payload in location:
            log_vuln(test_url, "Open Redirect")
    except:
        pass

def test_ssrf(url):
    test_url = url + urllib.parse.quote(ssrf_payload)
    try:
        r = requests.get(test_url, timeout=timeout)
        if r.status_code == 200 and ("localhost" in r.text or "127.0.0.1" in r.text):
            log_vuln(test_url, "Possible SSRF")
    except:
        pass

def test_csrf(url):
    try:
        r = requests.get(url, headers=csrf_test_headers, timeout=timeout)
        if "csrf" not in r.text.lower() and r.status_code == 200:
            log_vuln(url, "Potential CSRF (missing protection)")
    except:
        pass

def scan(url):
    if "=" not in url:
        return  # بدون پارامتر، عبور کن
    if url.endswith("="):
        base = url
    else:
        base = url + "&test="

    test_xss(base)
    test_redirect(base)
    test_ssrf(base)
    test_csrf(url)

def main():
    with open("urls.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"[+] شروع اسکن {len(urls)} URL ...")

    for url in urls:
        print(f"[*] تست: {url}")
        scan(url)

    print(f"\n[✓] اسکن تمام شد. نتایج در {output_file} ذخیره شد.")

if __name__ == "__main__":
    main()
