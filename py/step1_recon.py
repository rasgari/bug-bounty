import requests
import os
import json
from bs4 import BeautifulSoup

urls_file = "urls.txt"
out_dir = "out"
headers = {"User-Agent": "Mozilla/5.0 (WebHunter)"}
timeout = 6

def recon_url(url):
    result = {"url": url}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        soup = BeautifulSoup(r.text, 'html.parser')
        result["title"] = soup.title.string.strip() if soup.title else "N/A"
        result["headers"] = dict(r.headers)
        result["status_code"] = r.status_code
        result["technologies"] = detect_stack(r.text)
    except Exception as e:
        result["error"] = str(e)
    return result

def detect_stack(html):
    techs = []
    if "wp-content" in html: techs.append("WordPress")
    if "csrf-token" in html: techs.append("CSRF Token")
    if "react" in html.lower(): techs.append("React")
    if "vue" in html.lower(): techs.append("Vue.js")
    if "__VIEWSTATE" in html: techs.append("ASP.NET")
    return techs

def main():
    os.makedirs(out_dir, exist_ok=True)
    with open(urls_file) as f:
        urls = [line.strip() for line in f if line.strip()]
    
    results = []
    for url in urls:
        print(f"[+] در حال بررسی: {url}")
        info = recon_url(url)
        results.append(info)
    
    with open(f"{out_dir}/recon_raw.txt", "w") as f:
        for r in results:
            f.write(f"{r['url']} - {r.get('title', 'N/A')} - {r.get('status_code', '?')}\n")
    
    with open(f"{out_dir}/tech_stack.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("[✓] جمع‌آوری اطلاعات تمام شد.")

if __name__ == "__main__":
    main()
