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
echo "====================================================="
echo -e "${cyan}╲╲╲╲╲╲┏━┳━━━━━━━━┓╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃◯┃╭┻┻╮╭┻┻╮┃╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃╮┃┃╭╮┃┃╭╮┃┃╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃╯┃┗┻┻┛┗┻┻┻┻╮╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃◯┃╭╮╰╯┏━━━┳╯╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃╭┃╰┏┳┳┳┳┓◯┃╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┃╰┃◯╰┗┛┗┛╯╭┃╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲╲┻━━━━━━━━━━┻╲╲╲╲╲ ${NC}"
echo -e "${cyan}╲█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█ ${NC}"
echo -e "${cyan}╲█░░╦─╦╔╗╦─╔╗╔╗╔╦╗╔╗░░█ ${NC}"
echo -e "${cyan}╲█░░║║║╠─║─║─║║║║║╠─░░█ ${NC}"
echo -e "${cyan}╲█░░╚╩╝╚╝╚╝╚╝╚╝╩─╩╚╝░░█ ${NC}"
echo -e "${cyan}╲█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█ ${NC}"
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

if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	chmod +x /etc/rc.d/rc.local
else
	echo " [!] ดูเหมือนว่าคุณไม่ได้ใช้ตัวติดตั้งนี้ในระบบ Debian, Ubuntu หรือ CentOS"
	exit
fi
clear
color1='\e[031;1m'
color2='\e[34;1m'
color3='\e[0m'
	  echo  "----------------------------------------------------------------" | lolcat

	cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
	tram=$( free -m | awk 'NR==2 {print $2}' )
	swap=$( free -m | awk 'NR==4 {print $2}' )
	up=$(uptime|awk '{ $1=$2=$(NF-6)=$(NF-5)=$(NF-4)=$(NF-3)=$(NF-2)=$(NF-1)=$NF=""; print }')

	echo -e " [o] \e[032;1mCPU model:\e[0m $cname"
	echo -e " [o] \e[032;1mNumber of cores:\e[0m $cores"
	echo -e " [o] \e[032;1mCPU frequency:\e[0m $freq MHz"
	echo -e " [o] \e[032;1mTotal amount of ram:\e[0m $tram MB"
	echo -e " [o] \e[032;1mTotal amount of swap:\e[0m $swap MB"
	echo -e " [o] \e[032;1mSystem uptime:\e[0m $up"
	echo  "----------------------------------------------------------------" 
	echo  ">>>>>>>>>>>>>>>>>>>> MENU SCRIPT 0970267262 <<<<<<<<<<<<<<<<<<<<" | lolcat
	echo  "----------------------------------------------------------------" 
	echo -e " [o] |${color1} 1${color3}| สร้างบัญชีผู้ใช้"
	echo -e " [o] |${color1} 2${color3}| ลบบัญชีของผู้ใช้"
	echo -e " [o] |${color1} 3${color3}| รายชื่อผู้ใช้ทั้งหมด"
	echo -e " [o] |${color1} 4${color3}| เปลี่ยนรหัสผ่านผู้ใช้ใหม่"
	echo -e " [o] |${color1} 5${color3}| รายชื่อผู้ใช้ที่กำลังออนไลน์"
	echo -e " [o] |${color1} 6${color3}| แบนชื่อผู้ใช้"
	echo -e " [o] |${color1} 7${color3}| ปลดแบนชื่อผู้ใช้"
	echo -e " [o] |${color1} 8${color3}| ตั้งค่ารีบูทเซิฟเวอร์อัตโนมัติ"
	echo -e " [o] |${color1} 9${color3}| ตรวจสอบดาต้าที่ใช้ไปทั้งหมดในปัจจุบัน"
	echo -e " [o] |${color1}10${color3}| ทดสอบความเร็วอินเตอร์เน็ต"
	echo -e " [o] |${color1}11${color3}| รีสตาร์ทระบบ (สำหรับผู้ที่แก้ไขสคริปท์)"
	echo -e " [o] |${color1}12${color3}| ลิ้งค์ดาวน์โหลดคอนฟิกแบบใส่ชื่อผู้ใช้และรหัสผ่าน"
	echo -e " [o] |${color1}13${color3}| อัพเดตเมนู"
	echo -e " [o] |${color1}14${color3}| เก็บไฟล์สำรองข้อมูลผู้ใช้ หรือนำเข้าไฟล์สำรองข้อมูลผู้ใช้"
	echo -e " [o] |${color1}15${color3}| ยกเลิก"
	echo -e ""
	echo  "----------------------------------------------------------------" | lolcat
	read -p " [?] โปรดใส่ตัวเลือกของเมนู (ตัวเลข): " x
	echo  "----------------------------------------------------------------" | lolcat

if test $x -eq 1; then
	echo ""
	echo -e " [>] ${color1}ตัวอย่างการสร้างบัญชีผู้ใช้ ${color3} : herebird 12345 31"
	echo " [>] ชื่อผู้ใช้คือ herebird รหัสผ่านคือ 12345 หมดอายุในอีก 31 วัน"
	echo ""
	read -p " [>] Username Password Expired : " Login Passwd TimeActive
#	echo ""
#	read -p "Password : " Passwd
#	echo ""
#	read -p "Expired (Day) : " TimeActive

	IP=`dig +short myip.opendns.com @resolver1.opendns.com`
	useradd -e `date -d "$TimeActive days" +"%Y-%m-%d"` -s /bin/false -M $Login
	exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
	echo -e "$Passwd\n$Passwd\n"|passwd $Login &> /dev/null

cd /etc/openvpn/
cat > /etc/openvpn/$Login.ovpn <<END
client
dev tun
proto tcp
remote $IP:1194@static.tlcdn1.com/cdn.line-apps.com/line.naver.jp/nelo2-col.linecorp.com/mdm01.cpall.co.th/lvs.truehits.in.th/dl-obs.official.line.naver.jp 1194
http-proxy $IP 8080
http-proxy-retry
connect-retry 1
connect-timeout 120
resolv-retry infinite
route-method exe
nobind
ping 5
ping-restart 30
persist-key
persist-tun
persist-remote-ip
mute-replay-warnings
verb 3
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
<auth-user-pass>
$Login
$Passwd
</auth-user-pass>
cipher none
comp-lzo
script-security 3
key-proxy-DNS 8.8.8.8
key-proxy-DNS 8.8.4.4
management 127.0.0.1 5555
<ca>
-----BEGIN CERTIFICATE-----
MIID4DCCA0mgAwIBAgIJAM3S4jaLTQBoMA0GCSqGSIb3DQEBBQUAMIGnMQswCQYD
VQQGEwJJRDERMA8GA1UECBMIV2VzdEphdmExDjAMBgNVBAcTBUJvZ29yMRQwEgYD
VQQKEwtKdWFsU1NILmNvbTEUMBIGA1UECxMLSnVhbFNTSC5jb20xFDASBgNVBAMT
C0p1YWxTU0guY29tMRQwEgYDVQQpEwtKdWFsU1NILmNvbTEdMBsGCSqGSIb3DQEJ
ARYObWVAanVhbHNzaC5jb20wHhcNMTMxMTA4MTQwODA3WhcNMjMxMTA2MTQwODA3
WjCBpzELMAkGA1UEBhMCSUQxETAPBgNVBAgTCFdlc3RKYXZhMQ4wDAYDVQQHEwVC
b2dvcjEUMBIGA1UEChMLSnVhbFNTSC5jb20xFDASBgNVBAsTC0p1YWxTU0guY29t
MRQwEgYDVQQDEwtKdWFsU1NILmNvbTEUMBIGA1UEKRMLSnVhbFNTSC5jb20xHTAb
BgkqhkiG9w0BCQEWDm1lQGp1YWxzc2guY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDO0s4v72Y+V1z3XpkQD8hVjYyJk1PzpaNGpubtVXf7b/2vhvYBfE3X
46NvpgQejsAI4rW7XWMZrAjFzQBPE0zDAt1O0ukvGRFvHr16jLuC3cZCn3oQJ0+v
HD7Z16sUhKqLWRTGAf1LDvNR3eVmzzRfBF8L3h+ZGaQFW9gsw1tSSwIDAQABo4IB
EDCCAQwwHQYDVR0OBBYEFA5gsoPi0yORhvAA38zCXOQhX4wYMIHcBgNVHSMEgdQw
gdGAFA5gsoPi0yORhvAA38zCXOQhX4wYoYGtpIGqMIGnMQswCQYDVQQGEwJJRDER
MA8GA1UECBMIV2VzdEphdmExDjAMBgNVBAcTBUJvZ29yMRQwEgYDVQQKEwtKdWFs
U1NILmNvbTEUMBIGA1UECxMLSnVhbFNTSC5jb20xFDASBgNVBAMTC0p1YWxTU0gu
Y29tMRQwEgYDVQQpEwtKdWFsU1NILmNvbTEdMBsGCSqGSIb3DQEJARYObWVAanVh
bHNzaC5jb22CCQDN0uI2i00AaDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA
A4GBAL3ScsXaFFuBqkS8bDqDUkx2hYM2iAYx9ZEuz8DOgtenQiNcyety4YzWSE5b
1/4JSlrO0hoFAZpz6tZtB9XM5efx5zSEIn+w4+2bWUk34Ro2zM3JxwDUp1tTcpbT
T0G3VTuVrzgSMZV1unfbCHk6XR4VT3MmmoTl+97cmmMZgWV0
-----END CERTIFICATE-----
</ca>
END

	cp $Login.ovpn /home/vps/public_html/
	cd
	if [ ! -e /usr/local/bin/payload ]; then
        wget -O /usr/local/bin/payload "https://raw.githubusercontent.com/herebird/MENU-HEREBIRD/master/payload"
	chmod +x /usr/local/bin/payload
        fi
	clear
	cd
  	echo -e ""
	echo -e ""| lolcat
	echo -e "|       New Account Information SSH      |" | boxes -d dog | lolcat
	echo -e "==============[[-SERVER-PREMIUM-]]==============" | lolcat
	echo -e " [>] Host              : $IP                    " | lolcat
	echo -e " [>] Username          : $Login                 " | lolcat
	echo -e " [>] Password          : $Passwd                " | lolcat
	echo -e " [>] Port Dropbear     : 443,80                 " | lolcat
	echo -e " [>] Port OpenSSH      : 22,143                 " | lolcat
	echo -e " [>] Port Squid        : 8080,3128              " | lolcat
	echo -e " [>] Warning           : Max 2 login            " | lolcat
	echo -e "------------------------------------------------" | lolcat
	echo -e "      [>] สามารถใช้งานได้ถึง   : $exp              " | lolcat
	echo -e "================================================" | lolcat
	echo -e " [o] HACKING-DDOS-PHISING-SPAM-TORENT           " | lolcat
	echo -e " [o] HEREBIRD & OCSPANEL.INFO                   " | lolcat
	echo -e " [o] Script by 097-026-7262                     " | lolcat
	echo -e "================================================" | lolcat
	echo -e " [>] Config VPN:                                " | lolcat
	echo -e " http://$IP:81/client.ovpn                      " | lolcat
	echo -e "------------------------------------------------" | lolcat
	echo -e ""
	echo -e ""	

elif test $x -eq 2; then
	echo ""
	read -p "Username : " User

	if getent passwd $User > /dev/null 2>&1; then
		userdel $User
		echo ""
		echo -e " [>] ชื่อผู้ใช้ $User ได้ถูกลบออกจากระบบเรียบร้อยแล้ว" | lolcat
		echo ""
	else
		echo ""
		echo -e " [!] ไม่พบชื่อผู้ใช้ $User อยู่ในระบบ" | lolcat
		echo ""
	fi

elif test $x -eq 3; then
	if [ -f /etc/debian_version ]; then
		UIDN=1000
	elif [ -f /etc/redhat-release ]; then
		UIDN=500
	else
		UIDN=500
	fi

	echo ""
	echo "----------------------------------------------------------------"
	while read checklist
	do
		account="$(echo $checklist | cut -d: -f1)"
		ID="$(echo $checklist | grep -v nobody | cut -d: -f3)"
		exp="$(chage -l $account | grep "Account expires" | awk -F": " '{print $2}')"
		if [[ $ID -ge $UIDN ]]; then
		printf "%-17s %2s\n" "$account" "$exp"
		fi
	done < /etc/passwd
	total="$(awk -F: '$3 >= '$UIDN' && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
	echo -e "==============================[[ ]]=============================" | lolcat
	echo -e "  [o] รวมทั้งหมด : $total USER" | lolcat
	echo -e "==============================[[ ]]=============================" | lolcat
	echo -e ""

	echo -e "================================================================" | lolcat
	echo -e "  [>] HACKING-DDOS-PHISING-SPAM-TORENT                      " | lolcat
	echo -e "  [>] HEREBIRD & OCSPANEL.INFO                              " | lolcat
	echo -e "  [>] Script by 097-026-7262                                " | lolcat
	echo -e "================================================================" | lolcat
	echo -e " "| lolcat

elif test $x -eq 4; then
        echo ""
        read -p " [>] ชื่อผู้ใช้ที่ต้องการเปลี่ยนรหัสผ่าน : " username
        egrep "^$username" /etc/passwd >/dev/null
        if [ $? -eq 0 ]; then
        echo ""
        read -p " [>] กำหนดรหัสผ่านใหม่ของผู้ใช้ $username : " password

        egrep "^$username" /etc/passwd >/dev/null
        echo -e "$password\n$password" | passwd $username
        echo ""
        echo " [>] รหัสผ่านใหม่ของชื่อผู้ใช้ $username คือรหัส $password" | lolcat
        echo ""
        else
        echo ""
        echo " [?] ไม่พบชื่อผู้ใช้ $username อยู่ในระบบ" | lolcat
        echo ""
        fi

elif test $x -eq 5; then
	clear
        echo ""
        echo " [>] รายชื่อผู้ใช้ที่กำลังใช้งานอยู่ในขณะนี้"
        echo "================================================================";

        if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
        fi
        if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
        fi

        data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
        echo " [>] รายชื่อผู้ใช้ที่ใช้งานพอร์ตของ Dropbear";
        echo "(ID - Username - IP)";
        echo "================================================================";
        cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
        for PID in "${data[@]}"
        do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
		fi
        done
        echo " "
        echo " [>] รายชื่อผู้ใช้ที่ใช้งานพอร์ตของ OpenSSH";
        echo "(ID - Username - IP)";
        echo "================================================================";
        cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
        data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);

        for PID in "${data[@]}"
        do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi
        done
        if [ -f "/etc/openvpn/log.log" ]; then
	line=`cat /etc/openvpn/log.log | wc -l`
	a=$((3+((line-8)/2)))
	b=$(((line-8)/2))
	echo " "
	echo " [>] รายชื่อผู้ใช้ที่ใช้งาน OpenVPN";
	echo "(Username - IP - วันนี้ - เวลาที่เชื่อมต่อ)";
	echo "================================================================";
	cat /etc/openvpn/log.log | head -n $a | tail -n $b | cut -d "," -f 1,2,5 | sed -e 's/,/   /g' > /tmp/vpn-login-db.txt
	cat /tmp/vpn-login-db.txt
        fi

        echo " "
        echo " "
        echo "================================================================";
        echo " "

elif test $x -eq 6; then
        echo ""
        read -p "Username Ban : " username
        egrep "^$username" /etc/passwd >/dev/null
        if [ $? -eq 0 ]; then
        passwd -l $username
        echo ""
        echo " [>] ชื่อผู้ใช้ $username ได้ถูกแบนเรียบร้อยแล้ว" | lolcat
	echo ""
        else
	echo ""
        echo " [!] ไม่พบชื่อผู้ใช้ $username อยู่ในระบบ" | lolcat
	echo ""
        exit 1
        fi

elif test $x -eq 7; then
        echo ""
	read -p "Username Unban : " username
        egrep "^$username" /etc/passwd >/dev/null
        if [ $? -eq 0 ]; then
        passwd -u $username
        echo ""
        echo " [>] ชื่อผู้ใช้ $username ได้ถูกปลดแบนเรียบร้อยแล้ว" | lolcat
	echo ""
        else
	echo ""
        echo " [!] ไม่พบชื่อผู้ใช้ $username อยู่ในระบบ" | lolcat
	echo ""
        exit 1
        fi

elif test $x -eq 8; then
        if [ ! -e /usr/local/bin/reboot_otomatis ]; then
	echo '#!/bin/bash' > /usr/local/bin/reboot_otomatis 
	echo 'tanggal=$(date +"%m-%d-%Y")' >> /usr/local/bin/reboot_otomatis 
	echo 'waktu=$(date +"%T")' >> /usr/local/bin/reboot_otomatis 
	echo 'echo "เซิร์ฟเวอร์ได้รับการรีบูตเมื่อวันที่ $tanggal เวลา $waktu" >> /root/log-reboot.txt' >> /usr/local/bin/reboot_otomatis 
	echo '/sbin/shutdown -r now' >> /usr/local/bin/reboot_otomatis 
	chmod +x /usr/local/bin/reboot_otomatis
	fi

	echo "----------------------------------------------------------------"
	echo " [!] ตั้งค่าเวลารีบูทเซิฟเวอร์อัตโนมัติ" | lolcat
	echo "----------------------------------------------------------------"
	echo " [>] 1. รีบูททุกๆ 1 ชั่วโมง"
	echo " [>] 2. รีบูททุกๆ 6 ชั่วโมง"
	echo " [>] 3. รีบูททุกๆ 12 ชั่วโมง"
	echo " [>] 4. รีบูททุกๆ 1 วัน"
	echo " [>] 5. รีบูททุกๆ 1 สัปดาห์"
	echo " [>] 6. รีบูททุกๆ 1 เดือน"
	echo " [>] 7. ปิดการรีบูทอัตโนมัติ"
	echo " [>] 8. ดูบันทึกการรีบูทอัตโนมัติ"
	echo " [>] 9. ลบบันทึกการรีบูทอัตโนมัติ"
	echo ""
	read -p " [?] กรุณาเลือกหัวข้อที่ต้องการใช้งาน (ตัวเลข) : " x

	if test $x -eq 1; then
	echo "0 * * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 1 ชั่วโมงเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 2; then
	echo "0 */6 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 6 ชั่วโมงเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 3; then
	echo "0 */12 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 12 ชั่วโมงเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 4; then
	echo "0 0 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 1 วันเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 5; then
	echo "0 0 */7 * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 1 สัปดาห์เรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 6; then
	echo "0 0 1 * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ตั้งค่ารีบูทอัตโนมัติทุกๆ 1 เดือนเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 7; then
	rm -f /etc/cron.d/reboot_otomatis
	echo ""
	echo " [>] ปิดการรีบูทอัตโนมัติเรียบร้อยแล้ว" | lolcat
	echo ""
	elif test $x -eq 8; then
	if [ ! -e /root/log-reboot.txt ]; then
	echo ""
	echo " [>] ไม่มีบันทึกในปัจจุบัน" | lolcat
	echo ""
	else
	echo ""
	cat /root/log-reboot.txt
	echo ""
	fi
	elif test $x -eq 9; then
	echo "" > /root/log-reboot.txt
	echo ""
	echo " [>] ทำการลบบันทึกเรียบร้อยแล้ว" | lolcat
	echo ""
	else
	echo ""
	echo " [!] ไม่มีตัวเลือกในเมนู กรุณาลองใหม่อีกครั้ง" | lolcat
	echo ""
	exit
	fi

elif test $x -eq 9; then
        clear
        echo ""
        echo ""
        echo "ตรวจสอบดูตรงคำว่า Total ว่าได้ใช้ดาต้าไปทั้งหมดเท่าไหร่"
        echo "ในส่วนของแถว estimated คือการประมาณดาต้าที่ใช้ (ส่วนนี้ไม่ต้องสนใจ)"
        echo ""
        echo "หน่วยวัดขนาดของดาต้าจะแสดงเป็น MiB , GiB และ TiB"
        echo "     MiB คือเมกะไบต์ (Megabyte หรือ Mb)"
        echo "     GiB คิอกิกะไบต์ (Gigabyte หรือ Gb) (เช่น 1000Mb เท่ากับ 1Gb"
        echo "     TiB คือเทราไบต์ (Terabyte หรือ Tb) (เช่น 1Tb เท่ากับ 1000Gb)"
	echo ""
        echo "ส่วนของคำว่า month คือการแสดงบอกให้รู้ว่าแต่ละเดือนใช้งานดาต้าไปเท่าไหร่"
        echo "หน่วยวัด rx (Receive) คือขนาดการรับข้อมูลจากทางผู้ใช้งานอินเตอร์เน็ตไปยังเซิฟเวอร์"
        echo "หน่วยวัด tx (Transmit) คือขนาดการส่งข้อมูลออกจากเซิฟเวอร์ให้กับผู้ใช้งานอินเตอร์เน็ต"
        echo "หน่วยวัด avg. rate (Average Rate) คืออัตราการใช้งานดาต้าต่อวินาที"
        echo ""
	vnstat -m

elif test $x -eq 10; then
	speedtest --share

elif test $x -eq 11; then
        clear
        echo ""
        echo ""
        echo " [>] 1. หากคุณได้ทำการแก้ไขส่วนต่างๆภายในสคริปท์ และต้องการรีสตาร์ทระบบเดี๋ยวนี้"
        echo " [>] 2. หากคุณไม่ได้แก้ไขสคริปท์ คุณไม่จำเป็นที่จะต้องต้องรีสตาร์ทระะบบ"
        echo ""
	read -p " [?] กรุณาพิมพ์ตัวเลขที่ต้องการใช้งาน (ตัวเลข) : " x
	if test $x -eq 1; then
        clear
        echo ""
        echo " [>] OCSPANEL.INFO : Please Wait" | lolcat
        echo " [!] และจะกลับมาใช้งานได้อีกครั้งภายใน 30 วินาที"
        echo " [!] nginx ,openvpn ,cron ,ssh ,dropbear ,squid3 ....Restarting"
        echo ""
	/etc/init.d/nginx restart
	service openvpn restart
	service cron restart
	service ssh restart
	service dropbear restart
	service squid3 restart
        elif test $x -eq 2; then
        exit
        else
        clear
        menu
        fi

elif test $x -eq 12; then
if [ ! -e /home/vps/public_html/Client.ovpn ]; then
	IP=`dig +short myip.opendns.com @resolver1.opendns.com`

cat > /home/vps/public_html/Client.ovpn <<-END
client
dev tun
proto tcp
remote $IP:1194@static.tlcdn1.com/cdn.line-apps.com/line.naver.jp/nelo2-col.linecorp.com/mdm01.cpall.co.th/lvs.truehits.in.th/dl-obs.official.line.naver.jp 1194
http-proxy $IP 8080
http-proxy-retry
connect-retry 1
connect-timeout 120
resolv-retry infinite
route-method exe
nobind
ping 5
ping-restart 30
persist-key
persist-tun
persist-remote-ip
mute-replay-warnings
verb 3
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
auth-user-pass
cipher none
comp-lzo
script-security 3
key-proxy-DNS 8.8.8.8
key-proxy-DNS 8.8.4.4
<ca>
-----BEGIN CERTIFICATE-----
MIID4DCCA0mgAwIBAgIJAM3S4jaLTQBoMA0GCSqGSIb3DQEBBQUAMIGnMQswCQYD
VQQGEwJJRDERMA8GA1UECBMIV2VzdEphdmExDjAMBgNVBAcTBUJvZ29yMRQwEgYD
VQQKEwtKdWFsU1NILmNvbTEUMBIGA1UECxMLSnVhbFNTSC5jb20xFDASBgNVBAMT
C0p1YWxTU0guY29tMRQwEgYDVQQpEwtKdWFsU1NILmNvbTEdMBsGCSqGSIb3DQEJ
ARYObWVAanVhbHNzaC5jb20wHhcNMTMxMTA4MTQwODA3WhcNMjMxMTA2MTQwODA3
WjCBpzELMAkGA1UEBhMCSUQxETAPBgNVBAgTCFdlc3RKYXZhMQ4wDAYDVQQHEwVC
b2dvcjEUMBIGA1UEChMLSnVhbFNTSC5jb20xFDASBgNVBAsTC0p1YWxTU0guY29t
MRQwEgYDVQQDEwtKdWFsU1NILmNvbTEUMBIGA1UEKRMLSnVhbFNTSC5jb20xHTAb
BgkqhkiG9w0BCQEWDm1lQGp1YWxzc2guY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDO0s4v72Y+V1z3XpkQD8hVjYyJk1PzpaNGpubtVXf7b/2vhvYBfE3X
46NvpgQejsAI4rW7XWMZrAjFzQBPE0zDAt1O0ukvGRFvHr16jLuC3cZCn3oQJ0+v
HD7Z16sUhKqLWRTGAf1LDvNR3eVmzzRfBF8L3h+ZGaQFW9gsw1tSSwIDAQABo4IB
EDCCAQwwHQYDVR0OBBYEFA5gsoPi0yORhvAA38zCXOQhX4wYMIHcBgNVHSMEgdQw
gdGAFA5gsoPi0yORhvAA38zCXOQhX4wYoYGtpIGqMIGnMQswCQYDVQQGEwJJRDER
MA8GA1UECBMIV2VzdEphdmExDjAMBgNVBAcTBUJvZ29yMRQwEgYDVQQKEwtKdWFs
U1NILmNvbTEUMBIGA1UECxMLSnVhbFNTSC5jb20xFDASBgNVBAMTC0p1YWxTU0gu
Y29tMRQwEgYDVQQpEwtKdWFsU1NILmNvbTEdMBsGCSqGSIb3DQEJARYObWVAanVh
bHNzaC5jb22CCQDN0uI2i00AaDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA
A4GBAL3ScsXaFFuBqkS8bDqDUkx2hYM2iAYx9ZEuz8DOgtenQiNcyety4YzWSE5b
1/4JSlrO0hoFAZpz6tZtB9XM5efx5zSEIn+w4+2bWUk34Ro2zM3JxwDUp1tTcpbT
T0G3VTuVrzgSMZV1unfbCHk6XR4VT3MmmoTl+97cmmMZgWV0
-----END CERTIFICATE-----
</ca>
END
fi
        IP=`dig +short myip.opendns.com @resolver1.opendns.com`
        echo ""
        echo -e "Download Config	: http://$IP:81/Client.ovpn"
        echo ""

elif test $x -eq 13; then
	cd /usr/local/bin
	rm -f menu
	wget https://raw.githubusercontent.com/herebird/MENU-HEREBIRD/master/menu
	chmod +x menu
	cd

elif test $x -eq 14; then
clear
color1='\e[031;1m'
color2='\e[34;1m'
color3='\e[0m'
	echo ""
	echo " [>] กรุณาเลือกหัวข้อที่ต้องการในหมวดของ"
	echo "     เก็บไฟล์สำรองข้อมูลผู้ใช้ หรือนำเข้าไฟล์สำรองข้อมูลผู้ใช้"
	echo ""
	echo -e "|${color1} 1${color3}| เก็บไฟล์สำรองข้อมูลผู้ใช้ (Export Backup File)"
	echo -e "|${color1} 2${color3}| นำเข้าไฟล์สำรองข้อมูลผู้ใช้ (Import Backup File)"
	echo ""
	read -p " [?] กรุณาเลือกหัวข้อที่ต้องการใช้งาน (ตัวเลข) : " x


	if test $x -eq 1; then
	IP=`dig +short myip.opendns.com @resolver1.opendns.com`
	rm -r /home/vps/public_html/backup.tgz
	rm -r /home/vps/public_html/etc
	tar -czvf /home/vps/public_html/backup.tgz /etc/passwd /etc/group /etc/shadow /etc/gshadow
	clear
	echo ""
	echo " [>] ทำการเก็บไฟล์สำรองข้อมูลผู้ใช้เสร็จสิ้น..."
	echo " [>] ไฟล์สำรองข้อมูลผู้ใช้ถูกเก็บไว้ที่ /home/vps/public_html/"
	echo ""
	echo " [>] ลิ้งค์ดาวน์โหลดไฟล์สำรองข้อมูลผู้ใช้"
	echo " [>] Your File : $IP:85/backup.tgz"
	echo ""
	echo " [>] หมายเหตุ"
	echo " [>] การนำเข้าไฟล์สำรองข้อมูลผู้ใช้ไม่ควรปิดหรือลบ IP ปัจจุบันนี้ก่อนทำการนำเข้าไฟล์สำรองข้อมูลผู้ใช้ไปยัง IP ใหม่"
	echo ""

	elif test $x -eq 2; then
	rm -r /home/vps/public_html/backup.tgz
	rm -r /home/vps/public_html/etc
	clear
	echo ""
	echo ""
	read -p " [>] กรุณากรอกลิ้งค์ดาวน์โหลดไฟล์สำรองข้อมูลผู้ใช้ของคุณ : " Download
	wget -O /home/vps/public_html/backup.tgz "$Download"
	cd /home/vps/public_html
	tar -xzvf backup.tgz
	rm -r /etc/passwd /etc/group /etc/shadow /etc/gshadow
	cp -r etc/* /etc/
	echo ""
	echo " [>] ทำการนำเข้าไฟล์สำรองข้อมูลผู้ใช้เสร็จสิ้น..."
		sleep 5
		clear
		echo ""
		echo -e "|${color1} 1${color3}| เก็บไว้ (แนะนำ)"
		echo -e "|${color1} 2${color3}| ลบทิ้ง"
		echo ""
		read -p " [>] ต้องการเก็บไฟล์สำรองข้อมูลผู้ใช้ที่นำเข้าไว้หรือไม่ (ตัวเลข) : " x

		if test $x -eq 1; then
		echo ""
		echo " [>] ไฟล์สำรองข้อมูลผู้ใช้ของคุณยังคงถูกเก็บไว้ที่ /home/vps/public_html/ เช่นเดิม"
		echo ""
		elif test $x -eq 2; then
		rm -r /home/vps/public_html/backup.tgz
		rm -r /home/vps/public_html/etc
		echo ""
		echo " [>] ไฟล์สำรองข้อมูลผู้ใช้ที่คุณนำมากจาก IP อื่น"
		echo " [>] ถูกลบออกจากระบบแล้ว..."
		echo ""
		else
		echo ""
		echo " [!] คุณไม่ได้เลือกหัวข้อที่ให้มีให้เลือกไว้"
		echo " [>] ดังนั้นเราจึงไม่ลบไฟล์สำรองข้อมูลผู้ใช้ของคุณ"
		echo " [>] และยังคงเก็บไว้ที่ /home/vps/public_html/"
		echo ""
		exit
		fi

	else
	echo ""
	echo " [?] ไม่มีตัวเลือกในเมนู กรุณาลองใหม่อีกครั้ง"
	echo ""
	exit
	fi



elif test $x -eq 15; then
	exit

else
	clear
	menu
fi
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
