# nuclei

## Nuclei v3.4.10
بررسی نسخه
```
nuclei -version
```

بررسی کن Nuclei چطور نصب شده
```
which nuclei
nuclei -version
```

افزودن Go به PATH (اگر قبلاً نکردی)
```
export PATH=$PATH:$HOME/go/bin
```

---

نصب یا آپدیت آخرین نسخه
```
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```


آپدیت تمپلیت‌های Nuclei
```
nuclei -update-templates
```
مسیر تمپلیت‌ها

```
~/.local/nuclei-templates/
```
فول آپدیت
```
nuclei -ut
```

---

آپدیت Nuclei نصب‌شده از مخازن Kali (پیشنهاد نمی‌شود)

اگر از apt نصب کرده‌ای:

```
sudo apt update
sudo apt install --only-upgrade nuclei
```

⛔ نکته مهم:
نسخه‌های Kali معمولاً چند ورژن عقب‌تر از نسخه رسمی هستند و برای Bug Bounty توصیه نمی‌شوند.

🧹 حذف نسخه قدیمی برای جلوگیری از تداخل

اگر همزمان چند نسخه داری:
```
sudo rm -f /usr/bin/nuclei
sudo rm -f /usr/local/bin/nuclei
```

سپس دوباره با Go نصب کن.
