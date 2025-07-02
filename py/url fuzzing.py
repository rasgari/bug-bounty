import requests

# تنظیمات اولیه
target = "https://example.com"  # آدرس سایت هدف را اینجا وارد کنید
wordlist = "wordlist.txt"       # فایل لیست مسیرها (هر خط یک مسیر)

# خواندن لیست مسیرها
with open(wordlist, "r") as f:
    paths = [line.strip() for line in f if line.strip()]

# فاز کردن مسیرها
for path in paths:
    url = f"{target.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code not in [404, 400]:
            print(f"[+] {url} --> {r.status_code}")
    except Exception as e:
        continue
