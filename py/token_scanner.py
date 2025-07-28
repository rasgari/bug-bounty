import requests

# ---------- تنظیمات ----------
base_url = "https://example.com/authorize?token={payload}"
payload_file = "payloads.txt"
output_file = "valid_payloads.txt"
success_keywords = ["dashboard", "welcome", "admin"]  # کلیدواژه‌هایی که نشان‌دهنده موفقیت هستن
timeout = 5

# ---------- شروع اسکن ----------
with open(payload_file, "r") as f:
    payloads = [line.strip() for line in f if line.strip()]

found = []

print(f"[+] در حال تست {len(payloads)} پیلود...")

for payload in payloads:
    url = base_url.replace("{payload}", payload)
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200 and any(keyword in response.text.lower() for keyword in success_keywords):
            print(f"[✓] پیدا شد: {payload}")
            found.append(payload)
        else:
            print(f"[-] بی‌اثر: {payload}")
    except requests.exceptions.RequestException as e:
        print(f"[!] خطا در درخواست برای {payload}: {e}")

# ---------- ذخیره ----------
if found:
    with open(output_file, "w") as f:
        for p in found:
            f.write(p + "\n")
    print(f"\n[✓] {len(found)} پیلود مؤثر در {output_file} ذخیره شد.")
else:
    print("\n[-] هیچ پیلود مؤثری پیدا نشد.")
