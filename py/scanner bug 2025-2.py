# fast_vuln_scanner_api.py
from fastapi import FastAPI, HTTPException
import asyncio
import os
import re
from pydantic import BaseModel
from typing import List
import uvicorn

app = FastAPI()

KEYWORDS = [
    "auth", "token", "secret", "password", "api_key",
    "login", "redirect", "rce", "xss", "idor", "upload"
]

VULN_PATTERNS = [
    ("Authentication Bypass", re.compile(r"\b(auth)?(bypass|override|skip|unauthorized|unauthenticated)\b", re.I)),
    ("Hardcoded Credentials", re.compile(r"(password\s*=\s*['\"].+['\"]|secret\s*=\s*['\"].+['\"]|api[_\-]?key\s*=\s*['\"].+['\"])", re.I)),
    ("Open Redirect", re.compile(r"(redirect|url|goto|return)[\w\-_/]*=", re.I)),
    ("RCE", re.compile(r"(rce|exec|system|passthru|shell_exec)", re.I)),
    ("IDOR", re.compile(r"(id|user|uid|account)[\w\-_/]*=", re.I)),
]

results = {}

class ScanRequest(BaseModel):
    path: str

async def scan_file(filepath):
    findings = []
    try:
        async with aiofiles.open(filepath, mode='r', encoding='utf-8', errors='ignore') as f:
            content = await f.read()
            if not any(k in content for k in KEYWORDS):
                return []
            for vuln_name, pattern in VULN_PATTERNS:
                for m in pattern.finditer(content):
                    findings.append({
                        'file': filepath,
                        'vuln_type': vuln_name,
                        'match': m.group(0)
                    })
    except Exception as ex:
        findings.append({'file': filepath, 'error': str(ex)})
    return findings

@app.post("/start_scan/")
async def start_scan(req: ScanRequest):
    if not os.path.exists(req.path):
        raise HTTPException(status_code=404, detail="Path not found")
    all_files = []
    for root, dirs, files in os.walk(req.path):
        for file in files:
            if file.endswith(('.js','.json','.config','.env','.ini','.yaml','.yml','.xml','.toml','.php','.py','.html')):
                all_files.append(os.path.join(root, file))
    import aiofiles  # make sure to install aiofiles
    tasks = [scan_file(f) for f in all_files]
    scan_results = await asyncio.gather(*tasks)

    flat_results = [item for sublist in scan_results for item in sublist if item]

    results[req.path] = flat_results
    return {"message": f"Scan completed on {len(all_files)} files.", "found_vulnerabilities": len(flat_results)}

@app.get("/results/")
async def get_results(path: str):
    return results.get(path, [])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
