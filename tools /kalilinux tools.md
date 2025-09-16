## kalilinux tools


```
sudo apt update && sudo apt upgrade -y
```


```
sudo apt install -y golang git build-essential
```

```
nuclei -update-templates
```


```
chmod +x web_auto_scanner.py
python3 web_auto_scanner.py -d target.com --threads 20 --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

---

### subfinder

```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### httpx

```
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```


### nuclei

```
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### ffuf

```
go install -v github.com/ffuf/ffuf@latest
```

### dalfox

```
go install -v github.com/hahwul/dalfox/v2@latest
```

### waybackurls

```
go install -v github.com/tomnomnom/waybackurls@latest
```

### gau

```
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

---

```
sudo apt install -y seclists
```
wordlists in /usr/share/seclists/ یا /usr/share/wordlists/

---
