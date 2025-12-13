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
