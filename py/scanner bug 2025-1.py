import os
import re
import csv
from collections import defaultdict
from html import escape

# کلیدواژه‌های جستجو در فایل‌ها برای پیدا کردن نشانه‌ها
KEYWORDS = [
    "main", "app", "runtime", "bundle", "polyfills", "auth", "config",
    "settings", "local", "dev", "data", "api", "session", "user", "core",
    "client", "server", "utils", "base"
]

# الگوها و کلمات کلیدی آسیب‌پذیری بر اساس اهمیت (وزن دهی)
VULN_PATTERNS = [
    ("Authentication Bypass", re.compile(r"\b(auth)?(bypass|override|skip|unauthorized|unauthenticated)\b", re.I), 10),
    ("Sensitive Info Leak", re.compile(r"(password|secret|token|api[_\-]?key|credential|private[_\-]?key|jwt|session[_\-]?id)", re.I), 10),
    ("Hardcoded Credentials", re.compile(r"(password\s*=\s*['\"].+['\"]|secret\s*=\s*['\"].+['\"]|api[_\-]?key\s*=\s*['\"].+['\"])", re.I), 10),
    ("Config/Env File Disclosure", re.compile(r"\.(env|config|json|ini|yaml|yml|xml|toml)$", re.I), 9),
    ("Hidden Login Portals", re.compile(r"(login|signin|auth|portal|admin)[\w\-_/]*", re.I), 9),
    ("JWT Secrets & API Keys", re.compile(r"(jwt|api[_\-]?key|secret|token)", re.I), 10),
    ("Outdated Services CVE", re.compile(r"(deprecated|outdated|vulnerable|cve-\d{4}-\d+)", re.I), 8),
    ("Dependency Confusion", re.compile(r"(npm|pip|gem|maven|dependency)[\w\-_.]*", re.I), 8),
    ("File Upload Endpoints", re.compile(r"(upload|file)[\w\-_/]*", re.I), 8),
    ("RFI → RCE", re.compile(r"(remote[_\-]?file[_\-]?include|rfi|rce|exec|system|passthru|shell_exec)", re.I), 10),
    ("Open Redirection", re.compile(r"(redirect|url|goto|return)[\w\-_/]*=", re.I), 8),
    ("DOM-based XSS", re.compile(r"(innerHTML|document\.write|eval|setTimeout|setInterval)", re.I), 7),
    ("WebSocket Endpoints", re.compile(r"(ws://|wss://|WebSocket)", re.I), 6),
    ("Hidden Parameters", re.compile(r"(\?|\&)(\w+)=", re.I), 7),
    ("IDOR", re.compile(r"(id|user|uid|account|invoice|file)[\w\-_/]*=", re.I), 9)
]

# پسوندهای فایل‌هایی که بررسی میشوند
FILE_EXTENSIONS = ['.js', '.json', '.config', '.env', '.ini', '.yaml', '.yml', '.xml', '.toml', '.php', '.py', '.html']

def scan_files(root_path):
    findings = []
    for dirname, _, files in os.walk(root_path):
        for file in files:
            if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                filepath = os.path.join(dirname, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # آیا کلیدواژه ای دارد؟
                        if not any(k in content for k in KEYWORDS):
                            continue
                        # جستجوی الگوهای آسیب‌پذیری
                        for vuln_name, pattern, weight in VULN_PATTERNS:
                            matches = list(pattern.finditer(content))
                            if matches:
                                for m in matches:
                                    matched_text = m.group(0)
                                    findings.append({
                                        'file': filepath,
                                        'vuln_type': vuln_name,
                                        'match': matched_text,
                                        'weight': weight
                                    })
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")
    return findings

def save_csv(findings, filename='vulnerabilities_report.csv'):
    findings_sorted = sorted(findings, key=lambda x: x['weight'], reverse=True)
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['file', 'vuln_type', 'match', 'weight']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings_sorted:
            writer.writerow(item)

def save_html(findings, filename='vulnerabilities_report.html'):
    findings_sorted = sorted(findings, key=lambda x: x['weight'], reverse=True)

    html_content = """
    <html><head><meta charset='UTF-8'><title>Vulnerabilities Report</title>
    <style>
        body {font-family: Arial, sans-serif;}
        table {border-collapse: collapse; width: 100%;}
        th, td {border: 1px solid #ddd; padding: 8px;}
        th {background-color: #f2f2f2;}
        tr:hover {background-color: #f9f9f9;}
        .high {background-color: #fa8072;}
        .medium {background-color: #ffd700;}
        .low {background-color: #90ee90;}
    </style>
    </head><body>
    <h2>Vulnerabilities Scan Report</h2>
    <table>
    <tr><th>File Path</th><th>Vulnerability Type</th><th>Matched Text</th><th>Severity</th></tr>
    """

    for item in findings_sorted:
        sev_class = 'low'
        if item['weight'] >= 9:
            sev_class = 'high'
        elif item['weight'] >= 7:
            sev_class = 'medium'
        html_content += f"<tr class='{sev_class}'><td>{escape(item['file'])}</td><td>{escape(item['vuln_type'])}</td><td>{escape(item['match'])}</td><td>{item['weight']}</td></tr>"

    html_content += "</table></body></html>"

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Fast Vulnerability Scanner on Project Files")
    parser.add_argument('path', type=str, help="Root path to scan")
    args = parser.parse_args()

    findings = scan_files(args.path)
    if findings:
        save_csv(findings)
        save_html(findings)
        print(f"Scan complete! {len(findings)} vulnerabilities found.")
        print("Reports saved in 'vulnerabilities_report.csv' and 'vulnerabilities_report.html'")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()
