Bug Bounty Cheatsheet: Essential Commands

🔍 Find Subdomains
subfinder -d http://example.com -all -recursive -o subdomains.txt

🌐 Filter Live Subdomains
cat subdomains.txt | httpx -ports 80,443,8080 | tee live_subdomains.txt

📜 Find JavaScript Files
katana -u https://example.com -d 5 -jc | grep '\.js$' | tee alljs.txt
echo https://example.com | gau | grep '\.js$' | anew alljs.txt

🔗 Extract Valid URLs
cat Your.txt | uro | sort -u | httpx-toolkit -mc 200 -o OUTPUT.txt

🚨 Scan for Leaks in JS
cat OUTPUT.txt | jsleak -s -l -k | tee jsleak.txt

🔑 Search for Exposed Credentials
cat OUTPUT.txt | nuclei -t ~/nuclei-templates/http/exposures/ -c 30

📂 Directory Fuzzing
ffuf -request req.txt -request-proto https -w playloadpath -c -mr "root:"

📑 Find LFI Vulnerabilities
echo http://example.com | waybackurls | gf lfi | urldedupe | tee crawlfi.txt

🛡️ Find XSS Vulnerabilities
echo https://example.com | gau | gf xss | uro | Gxss | kxss | tee xss.txt
cat xss.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt

📈 Scan Alive Subdomains
httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > alivesubdomain.txt

📖 Find All URLs
katana -list https://example.com -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > allurls.txt
