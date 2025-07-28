import aiohttp
import asyncio
import urllib.parse
import os
from datetime import datetime
from jinja2 import Template

# -------------------
PAYLOAD_DIR = "payloads"
OUT_REPORT = f"out/vuln_scan_report.html"
CONCURRENT_REQS = 20
TIMEOUT = aiohttp.ClientTimeout(total=8)
VULN_TYPES = ["xss", "sql", "redirect", "ssrf", "cmd", "lfi"]
# -------------------

results = []

async def test_payload(session, base_url, param, payload, vuln_type):
    new_params = {param: payload}
    url_parts = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(url_parts[4]))
    query.update(new_params)
    url_parts[4] = urllib.parse.urlencode(query)
    target_url = urllib.parse.urlunparse(url_parts)

    try:
        async with session.get(target_url, timeout=TIMEOUT, allow_redirects=True) as resp:
            text = await resp.text()

            if vuln_type == "xss" and payload.lower() in text.lower():
                return (vuln_type, target_url, payload)
            elif vuln_type == "sql" and any(x in text.lower() for x in ["sql", "syntax", "mysql", "postgres"]):
                return (vuln_type, target_url, payload)
            elif vuln_type == "redirect" and "google.com" in resp.headers.get("Location", ""):
                return (vuln_type, target_url, payload)
            elif vuln_type == "ssrf" and "localhost" in text.lower():
                return (vuln_type, target_url, payload)
            elif vuln_type == "cmd" and "uid=" in text.lower():
                return (vuln_type, target_url, payload)
            elif vuln_type == "lfi" and "root:x:" in text:
                return (vuln_type, target_url, payload)

    except:
        return None

async def scan_url(session, url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return

    params = list(urllib.parse.parse_qs(parsed.query).keys())

    tasks = []
    for vuln_type in VULN_TYPES:
        payloads_file = os.path.join(PAYLOAD_DIR, f"{vuln_type}.txt")
        if not os.path.exists(payloads_file):
            continue
        with open(payloads_file) as f:
            payloads = [line.strip() for line in f if line.strip()]
        for param in params:
            for payload in payloads:
                tasks.append(test_payload(session, url, param, payload, vuln_type))

    found = await asyncio.gather(*tasks)
    for res in found:
        if res:
            results.append(res)

async def main():
    if not os.path.exists("out"):
        os.makedirs("out")

    with open("urls.txt") as f:
        urls = [line.strip() for line in f if line.strip()]

    connector = aiohttp.TCPConnector(limit=CONCURRENT_REQS, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [scan_url(session, url) for url in urls]
        await asyncio.gather(*tasks)

    build_html_report()

def build_html_report():
    html_template = """
    <html>
    <head>
        <title>WebHunter Report</title>
        <style>
            body { font-family: Arial; background: #f2f2f2; padding: 20px; }
            h2 { color: #333; }
            table { width: 100%; border-collapse: collapse; background: white; }
            th, td { padding: 10px; border: 1px solid #ddd; }
            th { background: #444; color: white; }
            .xss { background: #ffeeba; }
            .sql { background: #f5c6cb; }
            .redirect { background: #bee5eb; }
            .ssrf { background: #d4edda; }
            .cmd { background: #f8d7da; }
            .lfi { background: #d6d8d9; }
        </style>
    </head>
    <body>
        <h2>📊 WebHunter Vulnerability Report</h2>
        <table>
            <tr><th>Type</th><th>URL</th><th>Payload</th></tr>
            {% for vuln in results %}
            <tr class="{{ vuln[0] }}"><td>{{ vuln[0] }}</td><td><a href="{{ vuln[1] }}" target="_blank">{{ vuln[1] }}</a></td><td>{{ vuln[2] }}</td></tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    template = Template(html_template)
    html = template.render(results=results)

    with open(OUT_REPORT, "w") as f:
        f.write(html)

    print(f"\n[✓] اسکن تمام شد. گزارش در: {OUT_REPORT}")

if __name__ == "__main__":
    asyncio.run(main())
