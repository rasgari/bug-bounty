import glob

# مسیر فایل‌های txt (مثلاً همه فایل‌های .txt داخل پوشه current و old)
old_files = glob.glob("old/*.txt")   # فایل‌های قدیمی
new_files = glob.glob("new/*.txt")   # فایل‌های جدید

old_urls = set()
new_urls = set()

# خواندن URLهای قدیمی
for file in old_files:
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                old_urls.add(line)

# خواندن URLهای جدید
for file in new_files:
    with open(file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                new_urls.add(line)

# پیدا کردن URLهای جدید که در قدیمی‌ها نیست
diff_urls = new_urls - old_urls

# ذخیره در فایل خروجی
with open("new_only_urls.txt", "w", encoding="utf-8") as f:
    for url in sorted(diff_urls):
        f.write(url + "\n")

print(f"✅ {len(diff_urls)} URL جدید پیدا شد و در فایل 'new_only_urls.txt' ذخیره شد.")
