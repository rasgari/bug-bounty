# update
sudo apt update && sudo apt upgrade -y

# نصب پایه
sudo apt install -y golang git build-essential python3 python3-pip wget unzip

# set Go env (بزار در .bashrc یا اجرا کن همین الان)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# (برای ماندگاری) اضافه کن به ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# نصب ابزارها با go install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# نصب seclists (برای wordlists)
sudo apt install -y seclists

# اطمینان از اینکه باینری‌ها در PATH هستند
which subfinder httpx nuclei ffuf dalfox waybackurls gau
