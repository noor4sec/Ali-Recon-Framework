#! /bin/bash 
speedtest
echo "Installing Requirements...." 
sudo apt update -y
sudo apt upgrade -y
sudo apt install python -y
sudo apt install python2 -y
sudo apt install python3 -y
sudo apt install python-pip -y
sudo apt install python3-pip -y
sudo apt install git -y
sudo apt install php -y
sudo apt install lolcat -y
sudo apt install figlet -y
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing Go-Lang-------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Go-Lang....." | lolcat
wget https://go.dev/dl/go1.20.3.linux-amd64.tar.gz
mv go1.20.3.linux-amd64.tar.gz /root/
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing SubDomains Finders--------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Assestfinder..." 
go install github.com/tomnomnom/assetfinder@latest
cp /root/go/bin/assetfinder /usr/local/bin
echo "[+] Installing SubFinder......." 
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder /usr/local/bin/
echo "[+] Installing Findomain........" 
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && rm findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
findomain --help
echo "[+] Installing Amass......." 
go install -v github.com/OWASP/Amass/v3/...@master
cp /root/go/bin/amass /usr/local/bin/
echo "[+] Installing SubList3r........." 
git clone https://github.com/aboul3la/sublist3r.git 
mv sublist3r /opt/
pip3 install -r /opt/sublist3r/requirements.txt
#---------------------------------------------------------------------------------------------------------------------
#------------------------------------------Installing Url Crawlers ---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Waybackurls....." | lolcat
go install github.com/tomnomnom/waybackurls@latest
cp /root/go/bin/waybackurls /usr/local/bin/
echo "[+] Installing Katana....." 
go install github.com/projectdiscovery/katana/cmd/katana@latest
cp /root/go/bin/katana /usr/local/bin/
echo "[+] Installing gau - Get All Urls" | lolcat
go install github.com/lc/gau/v2/cmd/gau@latest
cp /root/go/bin/gau /usr/local/bin/
echo "[+] Installing gauplus........" | lolcat
go install github.com/bp0lr/gauplus@latest
cp /root/go/bin/gauplus /usr/local/bin/
echo "[+] Installing Paramspider......" | lolcat
git clone https://github.com/devanshbatham/paramspider.git
mv paramspider /opt/
pip3 install -r /opt/paramspider/requirements.txt
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing Subs Live Checker---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+]Installing httpx........" | lolcat
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx /usr/local/bin/
echo "[+]Installing httprobe......" | lolcat
go install github.com/tomnomnom/httprobe@latest 
cp /root/go/bin/httprobe /usr/local/bin/
#---------------------------------------------------------------------------------------------------------------------
#------------------------------------------------Installing Sql Map---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "Installing Sqlmap......" |lolcat
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
mv sqlmap /opt/
#----------------
echo "Installing qsreplace....." | lolcat
go install github.com/tomnomnom/qsreplace@latest
cp /root/go/bin/qsreplace /usr/local/bin/
echo "[+] Installing ffuf" | lolcat
go install github.com/ffuf/ffuf@latest
cp /root/go/bin/ffuf /usr/local/bin/
echo "[+] Installing gf Patterns" | lolcat
go install github.com/tomnomnom/gf@latest
cp /root/go/bin/gf /usr/local/bin/
echo "[+] Installing Dalfox..." | lolcat
go install github.com/hahwul/dalfox/v2@latest
cp /root/go/bin/dalfox /usr/local/bin/
echo "[+] Installing Gxss....." | lolcat
go install github.com/KathanP19/Gxss@latest
cp /root/go/bin/dalfox /usr/local/bin/
echo "[+] Installing kxss....." | lolcat
go install github.com/Emoe/kxss@latest
cp /root/go/bin/dalfox /usr/local/bin/
git clone https://github.com/projectdiscovery/fuzzing-templates.git
echo "Installing Nuclei...."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/local/bin
nuclei 
echo "Installing Fuzzing Templates...."
git clone https://github.com/projectdiscovery/fuzzing-templates.git
mv fuzzing-templates /root/
echo "Installing Notify...."
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
cp /root/go/bin/notify /usr/local/bin/
echo "Installing Clfuzz...."
