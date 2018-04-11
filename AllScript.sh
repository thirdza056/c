#!/bin/bash

# Check root
if [[ "$EUID" -ne 0 ]]; then
	echo ""
	echo "กรุณาเข้าสู่ระบบผู้ใช้ root ก่อนทำการติดตั้งสคริปท์"
	echo "คำสั่งเข้าสู่ระบบผู้ใช้ root คือ sudo -i"
	echo ""
fi

# Check OS can't run script
if [[ -e /etc/centos-release || -e /etc/redhat-release || -e /etc/system-release && ! -e /etc/fedora-release ]]; then
	OS=centos
	echo ""
	echo "สคริปท์นี้ยังไม่รอบรับ OS $OS"
	exit
elif [[ -e /etc/arch-release ]]; then
	OS=arch
	echo ""
	echo "สคริปท์นี้ยังไม่รอบรับ OS $OS"
	exit
elif [[ -e /etc/fedora-release ]]; then
	OS=fedora
	echo ""
	echo "สคริปท์นี้ยังไม่รอบรับ OS $OS"
	exit
fi


# Set IP
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
	IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi
IP2="s/xxxxxxxxx/$IP/g";

# Set OS Version
OS=debian
VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
IPTABLES='/etc/iptables/iptables.rules'
SYSCTL='/etc/sysctl.conf'
GROUPNAME=nogroup
RCLOCAL='/etc/rc.local'

# Set Localtime GMT +7
ln -fs /usr/share/zoneinfo/Asia/Thailand /etc/localtime

clear

# Color
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
black='\033[0;30m'
yellow='\033[0;33m'
magenta='\033[35m'
blue='\033[0;34m'
cyan='\033[0;36m'
white='\033[0;37m'

# Menu
echo "============================================"
echo "|${magenta}╲╲╲╲╲╲┏━┳━━━━━━━━┓╲╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃◯┃╭┻┻╮╭┻┻╮┃╲╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃╮┃┃╭╮┃┃╭╮┃┃╲╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃╯┃┗┻┻┛┗┻┻┻┻╮╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃◯┃╭╮╰╯┏━━━┳╯╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃╭┃╰┏┳┳┳┳┓◯┃╲╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┃╰┃◯╰┗┛┗┛╯╭┃╲╲╲╲╲ ${NC}"
echo "|${magenta}╲╲╲╲╲╲┻━━━━━━━━━━┻╲╲╲╲╲ ${NC}"
echo "|${magenta}╲█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█ ${NC}"
echo "|${magenta}╲█░░╦─╦╔╗╦─╔╗╔╗╔╦╗╔╗░░█ ${NC}"
echo "|${magenta}╲█░░║║║╠─║─║─║║║║║╠─░░█ ${NC}"
echo "|${magenta}╲█░░╚╩╝╚╝╚╝╚╝╚╝╩─╩╚╝░░█ ${NC}"
echo "|${magenta}╲█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█ ${NC}"
echo "====================================================="
echo "Debian 8-9 Ubuntu 14.04-16.04 Support"
echo -e "เมนูสคริป SCRIPT ${color1}By THIRDZ เวอร์ชั่นทดสอบ${color3}"
echo ""
echo -e "|${RED}1${NC}| OPENVPN (TERMINAL CONTROL) ${RED}✔   ${NC}"
echo -e "${RED}ฟังก์ชั่นที่ 1 และ 2 เลือกอยางใดอย่างหนึ่งเท่านั้น${NC}"
echo -e "|${RED}2${NC}| OPENVPN (PRITUNL CONTROL) ${GREEN}✔   ${NC}"
echo -e "|${RED}3${NC}| SSH + DROPBEAR ${yellow}✖   ${NC}"
echo -e "|${RED}4${NC}| WEB PANEL ${blue}✔   ${NC}"
echo -e "|${RED}5${NC}| VNSTAT (CHECK BANDWIDTH or DATA) ${cyan}✖   ${NC}"
echo -e "|${RED}6${NC}| SQUID PROXY ${magenta}✔   ${NC}"
echo ""
read -p "กรุณาเลือกฟังก์ชั่นที่ต้องการติดตั้ง (ตัวเลข) : " Menu

case $Menu in

	1)

#newclient () {
	#!/bin/bash
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;

flag=0

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0'`;
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd

echo "==========================================="
echo "            Installasi Dimulai             "
echo "==========================================="

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update
apt-get -y install wget curl
apt-get install ca-certificates

# Change to Time GMT+7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -q -O /etc/apt/sources.list https://raw.githubusercontent.com/Ojozambie/ultrav/master/sources.list.debian7
wget "http://www.dotdeb.org/dotdeb.gpg"
wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# update
apt-get update 
apt-get -y upgrade

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
#apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# Setting Vnstat
vnstat -u -i eth0
chown -R vnstat:vnstat /var/lib/vnstat
service vnstat restart

# install screenfetch
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/screenfetch-dev
mv screenfetch-dev /usr/bin/screenfetch-dev
chmod +x /usr/bin/screenfetch-dev
echo "clear" >> .profile
echo "screenfetch-dev" >> .profile


# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/Ojozambie/ultrav/master/badvpn-udpgw"
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
apt-get -y install snmpd;
wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/Ojozambie/ultrav/master/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://raw.githubusercontent.com/Ojozambie/ultrav/master/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.githubusercontent.com/Ojozambie/ultrav/master/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 3128 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="bannerssh"/g' /etc/default/dropbear
service ssh restart
service dropbear restart

# upgrade dropbear 2017
apt-get install zlib1g-dev
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
bzip2 -cd dropbear-2017.75.tar.bz2  | tar xvf -
cd dropbear-2017.75
.ure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# install vnstat gui
cd /home/vps/public_html/
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
sed -i "s/\$locale = 'en_US.UTF-8';/\$locale = 'en_US.UTF+8';/g" config.php
cd

# install fail2ban
apt-get -y install fail2ban;
service fail2ban restart

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/Ojozambie/ultrav/master/squid.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
wget "http://prdownloads.sourceforge.net/webadmin/webmin_1.840_all.deb"
dpkg --install webmin_1.840_all.deb;
apt-get -y -f install;
rm /root/webmin_1.840_all.deb
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart
service vnstat restart

# User Status
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/user-list.sh
mv ./user-list.sh /usr/local/bin/user-list.sh
chmod +x /usr/local/bin/user-list.sh

# Install Dos Deflate
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
cd

# instal UPDATE SCRIPT
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/update.sh
mv ./update.sh /usr/bin/update.sh
chmod +x /usr/bin/update.sh

# instal Buat Akun SSH/OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/buatakun.sh
mv ./buatakun.sh /usr/bin/buatakun.sh
chmod +x /usr/bin/buatakun.sh

# instal Generate Akun SSH/OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/generate.sh
mv ./generate.sh /usr/bin/generate.sh
chmod +x /usr/bin/generate.sh

# instal Generate Akun Trial
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/trial.sh
mv ./trial.sh /usr/bin/trial.sh
chmod +x /usr/bin/trial.sh

# instal  Ganti Password Akun SSH/VPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userpass.sh
mv ./userpass.sh /usr/bin/userpass.sh
chmod +x /usr/bin/userpass.sh

# instal Generate Akun SSH/OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userrenew.sh
mv ./userrenew.sh /usr/bin/userrenew.sh
chmod +x /usr/bin/userrenew.sh

# instal Hapus Akun SSH/OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userdelete.sh
mv ./userdelete.sh /usr/bin/userdelete.sh
chmod +x /usr/bin/userdelete.sh

# instal Cek Login Dropbear, OpenSSH & OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userlogin.sh
mv ./userlogin.sh /usr/bin/userlogin.sh
chmod +x /usr/bin/userlogin.sh

# instal Auto Limit Multi Login
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/autolimit.sh
mv ./autolimit.sh /usr/bin/autolimit.sh
chmod +x /usr/bin/autolimit.sh

# instal Auto Limit Script Multi Login
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/auto-limit-script.sh
mv ./auto-limit-script.sh /usr/local/bin/auto-limit-script.sh
chmod +x /usr/local/bin/auto-limit-script.sh

# instal Melihat detail user SSH & OpenVPN 
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userdetail.sh
mv ./userdetail.sh /usr/bin/userdetail.sh
chmod +x /usr/bin/userdetail.sh

# instal Delete Akun Expire
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/deleteuserexpire.sh
mv ./deleteuserexpire.sh /usr/bin/deleteuserexpire.sh
chmod +x /usr/bin/deleteuserexpire.sh

# instal  Kill Multi Login
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/autokilluser.sh
mv ./autokilluser.sh /usr/bin/autokilluser.sh
chmod +x /usr/bin/autokilluser.sh

# instal  Kill Multi Login2
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/autokill.sh
mv ./autokill.sh /usr/bin/autokill.sh
chmod +x /usr/bin/autokill.sh

# instal Auto Banned Akun
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userban.sh
mv ./userban.sh /usr/bin/userban.sh
chmod +x /usr/bin/userban.sh

# instal Unbanned Akun
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userunban.sh
mv ./userunban.sh /usr/bin/userunban.sh
chmod +x /usr/bin/userunban.sh

# instal Mengunci Akun SSH & OpenVPN
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userlock.sh
mv ./userlock.sh /usr/bin/userlock.sh
chmod +x /usr/bin/userlock.sh

# instal Membuka user SSH & OpenVPN yang terkunci
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userunlock.sh
mv ./userunlock.sh /usr/bin/userunlock.sh
chmod +x /usr/bin/userunlock.sh

# instal Melihat daftar user yang terkick oleh perintah user-limit
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/loglimit.sh
mv ./loglimit.sh /usr/bin/loglimit.sh
chmod +x /usr/bin/loglimit.sh

# instal Melihat daftar user yang terbanned oleh perintah user-ban
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/logban.sh
mv ./logban.sh /usr/bin/logban.sh
chmod +x /usr/bin/logban.sh

# instal Set Auto Reboot
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/autoreboot.sh
mv ./autoreboot.sh /usr/bin/autoreboot.sh
chmod +x /usr/bin/autoreboot.sh

# Install SPEED tES
cd
apt-get install python
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/speedtest.py.sh
mv ./speedtest.py.sh /usr/bin/speedtest.py.sh
chmod +x /usr/bin/speedtest.py.sh

# instal autolimitscript
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/auto-limit-script.sh
mv ./auto-limit-script.sh /usr/bin/auto-limit-script.sh
chmod +x /usr/bin/auto-limit-script.sh

# instal userdelete
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/userdelete.sh
mv ./userdelete.sh /usr/bin/userdelete.sh
chmod +x /usr/bin/userdelete.sh

# instal diagnosa
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/diagnosa.sh
mv ./diagnosa.sh /usr/bin/diagnosa.sh
chmod +x /usr/bin/diagnosa.sh

# instal ram
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/ram.sh
mv ./ram.sh /usr/bin/ram.sh
chmod +x /usr/bin/ram.sh

# log install
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/log-install.sh
mv ./log-install.sh /usr/bin/log-install.sh
chmod +x /usr/bin/log-install.sh

# edit ubah-port
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/ubahport.sh
mv ./ubahport.sh /usr/bin/ubahport.sh
chmod +x /usr/bin/ubahport.sh

# edit-port-dropbear
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/edit-port-dropbear.sh
mv ./edit-port-dropbear.sh /usr/bin/edit-port-dropbear.sh
chmod +x /usr/bin/edit-port-dropbear.sh

# edit-port-openssh
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/edit-port-openssh.sh
mv ./edit-port-openssh.sh /usr/bin/edit-port-openssh.sh
chmod +x /usr/bin/edit-port-openssh.sh

# edit-port-openvpn
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/edit-port-openvpn.sh
mv ./edit-port-openvpn.sh /usr/bin/edit-port-openvpn.sh
chmod +x /usr/bin/edit-port-openvpn.sh

# edit-port-openvpn
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/edit-port-squid.sh
mv ./edit-port-squid.sh /usr/bin/edit-port-squid.sh
chmod +x /usr/bin/edit-port-squid.sh

# restart
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/restart.sh
mv ./restart.sh /usr/bin/restart.sh
chmod +x /usr/bin/restart.sh

# restart-dropbear
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/restart-dropbear.sh
mv ./restart-dropbear.sh /usr/bin/restart-dropbear.sh
chmod +x /usr/bin/restart-dropbear.sh

# restart-squid
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/restart-squid.sh
mv ./restart-squid.sh /usr/bin/restart-squid.sh
chmod +x /usr/bin/restart-squid.sh

# restart-openvpn
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/restart-openvpn.sh
mv ./restart-openvpn.sh /usr/bin/restart-openvpn.sh
chmod +x /usr/bin/restart-openvpn.sh

# restart-webmin
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/restart-webmin.sh
mv ./restart-webmin.sh /usr/bin/restart-webmin.sh
chmod +x /usr/bin/restart-webmin.sh

# disable-user-expire
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/disable-user-expire.sh
mv ./disable-user-expire.sh /usr/bin/disable-user-expire.sh
chmod +x /usr/bin/disable-user-expire.sh

# bannerssh
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/bannerssh
mv ./bannerssh /bannerssh
chmod 0644 /bannerssh
service dropbear restart
service ssh restart

# Install Menu
cd
wget https://raw.githubusercontent.com/Ojozambie/ultrav/master/menu
mv ./menu /usr/local/bin/menu
chmod +x /usr/local/bin/menu

# download script
cd
wget -q -O /usr/bin/welcomeadmin https://raw.githubusercontent.com/Ojozambie/ultrav/master/welcome.sh
wget -O /etc/bannerssh "https://raw.githubusercontent.com/Ojozambie/ultrav/master/bannerssh"
echo "0 0 * * * root /sbin/reboot" > /etc/cron.d/reboot
echo "* * * * * service dropbear restart" > /etc/cron.d/dropbear

# Admin Welcome
chmod +x /usr/bin/welcomeadmin
echo "welcomeadmin" >> .profile

# Restart Service
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service vnstat restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart

cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Setup by Ibnu Fachrizal"  | tee -a log-install.txt
echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)"  | tee -a log-install.txt
echo "OpenSSH  : 22, 143"  | tee -a log-install.txt
echo "Dropbear : 80, 109, 110, 443"  | tee -a log-install.txt
echo "Squid3   : 8080, 8000, 3128 (limit to IP SSH)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt
echo "nginx    : 81"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "axel"    | tee -a log-install.txt
echo "bmon"    | tee -a log-install.txt
echo "htop"    | tee -a log-install.txt
echo "iftop"    | tee -a log-install.txt
echo "mtr"    | tee -a log-install.txt
echo "rkhunter"    | tee -a log-install.txt
echo "nethogs: nethogs venet0"    | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo "Webmin   : http://$MYIP:10000/"  | tee -a log-install.txt
echo "vnstat   : http://$MYIP:81/vnstat/"  | tee -a log-install.txt
echo "MRTG     : http://$MYIP:81/mrtg/"  | tee -a log-install.txt
echo "Timezone : Asia/Jakarta"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "IPv6     : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "VPS REBOOT TIAP JAM 00.00 !"  | tee -a log-install.txt
echo""  | tee -a log-install.txt
echo "Please Reboot your VPS !"  | tee -a log-install.txt
echo "================================================"  | tee -a log-install.txt
echo "Script Created By Ibnu Fachrizal"  | tee -a log-install.txt
echo "กรุณาพิมพ์ menu เพื่อเข้าสู่ตัวเลือก"  | tee -a log-install.txt
cd ~/
rm -f /root/debian7.sh
rm -f /root/speedtest.py.sh
rm -rf /root/mrtg-mem.sh
rm -rf /root/dropbear-2017.75.tar.bz2
rm -rf /root/ddos-deflate-master.zip
	;;

	2)

	# Debian 8
	if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then

	echo "deb http://repo.mongodb.org/apt/debian jessie/mongodb-org/3.6 main" > /etc/apt/sources.list.d/mongodb-org-3.6.list
	echo "deb http://repo.pritunl.com/stable/apt jessie main" > /etc/apt/sources.list.d/pritunl.list
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
	apt-get update
	apt-get --assume-yes install pritunl mongodb-org
	systemctl start mongod pritunl
	systemctl enable mongod pritunl

		while [[ $Squid3 != "Y" && $Squid3 != "N" ]]; do

			echo ""
			echo "คุณต้องการติดตั้ง Squid Proxy หรือไม่"
			read -p "ขอแนะนำให้ติดตั้ง (Y or N) : " -e -i Y Squid3

		done

			if [[ "$Squid3" = "N" ]]; then

			echo ""
			echo "Source by Mnm Ami"
			echo "Donate via TrueMoney Wallet : 082-038-2600"
			echo ""
			echo "Install Pritunl Finish"
			echo "No Proxy"
			echo ""
			echo "Pritunl : http://$IP"
			echo ""
			pritunl setup-key
			echo ""
			exit

			fi

	# Debian 9
	elif [[ "$VERSION_ID" = 'VERSION_ID="9"' ]]; then

	echo "deb http://repo.pritunl.com/stable/apt stretch main" > /etc/apt/sources.list.d/pritunl.list
	apt-get -y install dirmngr
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
	apt-get update
	apt-get --assume-yes install pritunl mongodb-server
	systemctl start mongodb pritunl
	systemctl enable mongodb pritunl

		while [[ $Squid != "Y" && $Squid != "N" ]]; do

			echo ""
			echo "คุณต้องการติดตั้ง Squid Proxy หรือไม่ ?"
			read -p "ขอแนะนำให้ติดตั้ง (Y or N) : " -e -i Y Squid

		done

			if [[ "$Squid" = "N" ]]; then

			echo ""
			echo "Source by Mnm Ami"
			echo "Donate via TrueMoney Wallet : 082-038-2600"
			echo ""
			echo "Install Pritunl Finish"
			echo "No Proxy"
			echo ""
			echo "Pritunl : http://$IP"
			echo ""
			pritunl setup-key
			echo ""
			exit

			fi

	# Ubuntu 14.04
	elif [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then

	echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.6 multiverse" > /etc/apt/sources.list.d/mongodb-org-3.6.list
	echo "deb http://repo.pritunl.com/stable/apt trusty main" > /etc/apt/sources.list.d/pritunl.list
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
	apt-get update
	apt-get --assume-yes install pritunl mongodb-org
	service pritunl start

		while [[ $Squid3 != "Y" && $Squid3 != "N" ]]; do

			echo ""
			echo "คุณต้องการติดตั้ง Squid Proxy หรือไม่ ?"
			read -p "ขอแนะนำให้ติดตั้ง (Y or N) : " -e -i Y Squid3

		done

			if [[ "$Squid3" = "N" ]]; then

			echo ""
			echo "Source by Mnm Ami"
			echo "Donate via TrueMoney Wallet : 082-038-2600"
			echo ""
			echo "Install Pritunl Finish"
			echo "No Proxy"
			echo ""
			echo "Pritunl : http://$IP"
			echo ""
			pritunl setup-key
			echo ""
			exit

			fi

	# Ubuntu 16.04
	elif [[ "$VERSION_ID" = 'VERSION_ID="16.04"' ]]; then

	echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.6 multiverse" > /etc/apt/sources.list.d/mongodb-org-3.6.list
	echo "deb http://repo.pritunl.com/stable/apt xenial main" > /etc/apt/sources.list.d/pritunl.list
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
	apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
	apt-get update
	apt-get --assume-yes install pritunl mongodb-org
	systemctl start pritunl mongod
	systemctl enable pritunl mongod

		while [[ $Squid != "Y" && $Squid != "N" ]]; do

			echo ""
			echo "คุณต้องการติดตั้ง Squid Proxy หรือไม่ ?"
			read -p "ขอแนะนำให้ติดตั้ง (Y or N) : " -e -i Y Squid

		done

			if [[ "$Squid" = "N" ]]; then

			echo ""
			echo "Source by Mnm Ami"
			echo "Donate via TrueMoney Wallet : 082-038-2600"
			echo ""
			echo "Install Pritunl Finish"
			echo "No Proxy"
			echo ""
			echo "Pritunl : http://$IP"
			echo ""
			pritunl setup-key
			echo ""
			exit

			fi

	fi

	# Install Squid
	if [[ "$Squid3" = "Y" ]]; then

apt-get -y install squid3
cat > /etc/squid3/squid.conf <<END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/255.255.255.255
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname OPENEXTRA.NET
END
sed -i $IP2 /etc/squid3/squid.conf;
service squid3 restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install Pritunl Finish"
echo "Proxy : $IP"
echo "Port  : 8080"
echo ""
echo "Pritunl : http://$MYIP"
echo ""
pritunl setup-key
echo ""

	elif [[ "$Squid" = "Y" ]]; then

apt-get -y install squid
cat > /etc/squid/squid.conf <<END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/255.255.255.255
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname OPENEXTRA.NET
END
sed -i $IP2 /etc/squid/squid.conf;
service squid restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install Pritunl Finish"
echo "Proxy : $IP"
echo "Port  : 8080"
echo ""
echo "Pritunl : http://$IP"
echo ""
pritunl setup-key
echo ""

	fi

	;;

	3)
	echo "3 กรุณารอสักนิด ขณะนี้ยังไม่ได้ติดตั้งคำสั่งนี้"
	;;

	4)
	if [ $USER != 'root' ]; then
	echo "Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;

if [[ -e /etc/debian_version ]]; then
	#OS=debian
	RCLOCAL='/etc/rc.local'
else
	echo "Anda tidak menjalankan script ini pada OS Debian"
	exit
fi

# go to root
cd

#https://github.com/adenvt/OcsPanels/wiki/tutor-debian

clear
echo ""
echo "Saya perlu bertanya beberapa soalan sebelum memulakan setup"
echo "Anda boleh membiarkan pilihan default dan hanya tekan enter jika Anda setuju dengan pilihan tersebut"
echo ""
echo "Pertama saya perlu tahu password baru user root MySQL:"
read -p "Password baru: " -e -i kaizen DatabasePass
echo ""
echo "Terakhir, sebutkan Nama Database untuk OCS Panels"
echo "Sila gunakan satu kata saja, tiada karakter khusus selain Underscore (_)"
read -p "Nama Database: " -e -i OCS_PANEL DatabaseName
echo ""
echo "Okey, OCS Panel anda bersedia untuk di Install"
read -n1 -r -p "Tekan sebarang keyword untuk memulakan..."

#apt-get update
apt-get update -y
apt-get install build-essential expect -y
apt-get install -y mysql-server

#mysql_secure_installation
so1=$(expect -c "
spawn mysql_secure_installation; sleep 3
expect \"\";  sleep 3; send \"\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect eof; ")
echo "$so1"
#\r
#Y
#pass
#pass
#Y
#Y
#Y
#Y

chown -R mysql:mysql /var/lib/mysql/
chmod -R 755 /var/lib/mysql/

apt-get install -y nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt


# Install Web Server
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default

wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/rasta-team/MyVPS/master/nginx.conf"
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/rasta-team/MyVPS/master/vps.conf"
sed -i 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php5/fpm/php.ini
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf

mkdir -p /home/vps/public_html

useradd -m vps

mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html

service php5-fpm restart
service nginx restart

apt-get -y install git
cd /home/vps/public_html
git init
git remote add origin https://github.com/rzengineer/Ocs-Panel-Reborns.git
git pull origin master
chmod 777 /home/vps/public_html/application/config/database.php


chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html

#mysql -u root -p
so2=$(expect -c "
spawn mysql -u root -p; sleep 3
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;EXIT;\r\"
expect eof; ")
echo "$so2"
#pass
#CREATE DATABASE IF NOT EXISTS OCS_PANEL;EXIT;

#chmod 777 /home/vps/public_html/application/controllers/topup/wallet/cookie.txt
#chmod 777 /home/vps/public_html/application/config/database.php
#chmod 755 /home/vps/public_html/application/controllers/topup/wallet/config.php
#chmod 755 /home/vps/public_html/application/controllers/topup/wallet/manager/TrueWallet.php
#chmod 755 /home/vps/public_html/application/controllers/topup/wallet/manager/Curl.php
#chmod 755 /home/vps/public_html/topup/confirm.php
#chmod 755 /home/vps/public_html/topup/get.php
#chmod 755 /home/vps/public_html/topup/index.php
#chmod 755 /home/vps/public_html/topup/input.php


clear
echo ""
echo "-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-"
echo ""
echo "เปิดเบราว์เซอร์และเข้าถึงที่อยู่ http://$MYIP:81/ และกรอกข้อมูล 2 ด้านล่าง!"
echo "Database:"
echo "- Database Host: localhost"
echo "- Database Name: $DatabaseName"
echo "- Database User: root"
echo "- Database Pass: $DatabasePass"
echo ""
echo "Admin Login:"
echo "- Username: ตามที่[พี่เทพ]ต้องการ"
echo "- Password New: ตามที่[พี่เทพ]ต้องการ"
echo "- Confirm Password New: ตามที่[พี่เทพ]ต้องการ"
echo ""
echo "นำข้อมูลไปติดตั้งที่ Browser และรอให้เสร็จสิ้นจากนั้นปิด Browser และกลับมาที่นี่ (Putty) แล้วกด [ENTER]!"

sleep 3
echo ""
read -p "หากขั้นตอนข้างต้นเสร็จสิ้นโปรดกดปุ่ม [Enter] เพื่อดำเนินการต่อ ..."
echo ""
read -p "หาก [ พี่เทพ ] มั่นใขว่าขั้นตอนข้างต้นได้ทำเสร็จแล้วโปรดกดปุ่ม [Enter] เพื่อดำเนินการต่อ ..."
echo ""

cd /root

apt-get update

service webmin restart

apt-get -y --force-yes -f install libxml-parser-perl

echo "unset HISTFILE" >> /etc/profile

#sleep 5
#echo "กรุณาตั้งค่า ระบบเติมเงิน หมายเลขอ้างอิงวอลเลต"

#sleep 5
#nano /home/vps/public_html/application/controllers/topup/wallet/config.php

# info
clear
echo "================ การติดตั้งเสร็จสิ้น พร้อมใช้งาน ================" | tee -a log-install.txt
echo "กรุณาเข้าสู่ระบบ OCS Panel ที่ http://$MYIP:81/" | tee -a log-install.txt

echo "" | tee -a log-install.txt
#echo "บันทึกการติดตั้ง --> /root/log-install.txt" | tee -a log-install.txt
#echo "" | tee -a log-install.txt
echo "โปรดรีบูต VPS ของคุณ!" | tee -a log-install.txt
echo "=========================================================" | tee -a log-install.txt
rm -rf /home/vps/public_html/install
	
	;;

	5)
	echo "5 กรุณารอสักนิด ขณะนี้ยังไม่ได้ติดตั้งคำสั่งนี้"
	# Install Vnstat
#	apt-get -y install vnstat
#	vnstat -u -i eth0

	# Install Vnstat GUI

#	rm /etc/apt/sources.list
#	cp /root/backup/sources.list /etc/apt/

	;;

	6)

	if [[ "$VERSION_ID" = 'VERSION_ID="8"' || "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then

apt-get -y install squid3
cat > /etc/squid3/squid.conf <<END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/255.255.255.255
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname OPENEXTRA.NET
END
sed -i $IP2 /etc/squid3/squid.conf;
service squid3 restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install Squid Proxy Finish"
echo "Proxy : $IP"
echo "Port  : 8080"
echo ""

	elif [[ "$VERSION_ID" = 'VERSION_ID="9"' || "$VERSION_ID" = 'VERSION_ID="16.04"' ]]; then

apt-get -y install squid
cat > /etc/squid/squid.conf <<END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/255.255.255.255
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname OPENEXTRA.NET
END
sed -i $IP2 /etc/squid/squid.conf;
service squid restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install Squid Proxy Finish"
echo "Proxy : $IP"
echo "Port  : 8080"
echo ""

	fi

	;;

esac
