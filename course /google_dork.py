#!/usr/bin/env python3
"""
simple_google_dork.py
- ورودی: domain (مثلاً example.com)
- خروجی: results_<domain>.txt (دُرک + نمونهٔ query)
توضیح: این اسکریپت **درخواست مستقیم به گوگل** نمی‌فرستد تا rate-limit/blocked نشوی.
به جای آن، دُرک‌ها را تولید می‌کند تا تو خودت (یا ابزارِ قانونی) آنها را اجرا کنی.
"""

import sys
from pathlib import Path

DORKS = [
    'site:{domain} inurl:admin OR inurl:login',
    'site:{domain} "index of" "backup"',
    'site:{domain} filetype:env OR filetype:ini "DB_PASSWORD"',
    'site:{domain} filetype:sql "password" OR "credential"',
    'site:{domain} filetype:log intext:password'
]

def gen(domain):
    out = Path(f'results_{domain}.txt')
    with out.open('w', encoding='utf-8') as f:
        for d in DORKS:
            q = d.format(domain=domain)
            f.write(q + '\n')
    print('Done. Dork queries saved to', out)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 simple_google_dork.py target.com')
        sys.exit(1)
    gen(sys.argv[1])
