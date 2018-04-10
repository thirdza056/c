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

# Menu
echo ""
echo -e "${RED}  (\_(\  ${NC}"
echo -e "${RED} (=’ :’) :* ${NC} Script by Mnm Ami"
echo -e "${RED}  (,(”)(”) °.¸¸.• ${NC}"
echo ""
echo "Debian 8-9 Ubuntu 14.04-16.04 Support"
echo -e "FUNCTION SCRIPT ${color1}✿.｡.:* *.:｡✿*ﾟ’ﾟ･✿.｡.:*${color3}"
echo ""
echo -e "|${RED}1${NC}| OPENVPN (TERMINAL CONTROL) ${RED}✖   ${NC}"
echo -e "${RED}ฟังก์ชั่นที่ 1 และ 2 เลือกอยางใดอย่างหนึ่งเท่านั้น${NC}"
echo -e "|${RED}2${NC}| OPENVPN (PRITUNL CONTROL) ${GREEN}✔   ${NC}"
echo -e "|${RED}3${NC}| SSH + DROPBEAR ${RED}✖   ${NC}"
echo -e "|${RED}4${NC}| WEB PANEL ${RED}✖   ${NC}"
echo -e "|${RED}5${NC}| VNSTAT (CHECK BANDWIDTH or DATA) ${RED}✖   ${NC}"
echo -e "|${RED}6${NC}| SQUID PROXY ${GREEN}✔   ${NC}"
echo ""
read -p "กรุณาเลือกฟังก์ชั่นที่ต้องการติดตั้ง (ตัวเลข) : " Menu

case $Menu in

	1)

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
		clear
		echo ""
		echo "ระบบตรวจสอบพบว่าได้ทำการติดตั้งเซิฟเวอร์ OpenVPN ไปแล้ว"
		echo ""
		echo -e "|${RED}1${NC}| ถอดถอนเซิฟเวอร์ OpenVPN"
		echo -e "|${RED}2${NC}| ยกเลิก"
		echo ""
		read -p "หรือหากต้องการทำสิ่งใด โปรดเลือกหัวข้อด้านบนนี้ : " option

		case $option in

			1) 
			echo ""
			read -p "แน่ใจใช่หรือไม่ว่าต้องการถอดถอนเซิฟเวอร์  OpenVPN : " -e -i N REMOVE

			if [[ "$REMOVE" = 'Y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP

				else

					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL

					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi

				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi

				apt-get remove --purge -y openvpn
				rm -rf /etc/openvpn
				echo ""
				echo "เซิฟเวอร์ OpenVPN ได้ถูกถอดถอนเรียบร้อยแล้ว"
			else
				exit
			fi
			exit
			;;

			2)
			exit
			;;

		esac
	done

else

	clear
	echo ""
	read -p "IP : " -e -i $IP IP
	read -p "Port : " -e -i 1194 PORT
	read -p "Hostname Proxy : " -e -i Hostname.net HOSTNAME
	read -p "Port Proxy : " -e -i 8080 PROXY
	echo ""
	echo -e "|${RED}1${NC}| TCP (แนะนำ)"
	echo -e "|${RED}2${NC}| UDP"
	read -p "Protocal : " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=tcp
		;;
		2) 
		PROTOCOL=udp
		;;
	esac
	echo ""
	echo -e "|${RED}1${NC}| DNS Current system"
	echo -e "|${RED}2${NC}| DNS Google"
	read -p "DNS : " -e -i 1 DNS
	echo ""
	read -p "Client Name : " -e -i Client CLIENT
	echo ""
	read -n1 -r -p "กดเอนเตอร์ครั้งสุดท้ายเพื่อเริ่มการติดตั้ง..."

	# Install Essential Package
	apt-get update
	apt-get install openvpn iptables openssl ca-certificates -y

	# Delete old easy-rsa
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.3.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.3/EasyRSA-3.0.3.tgz"
	tar xzf ~/EasyRSA-3.0.3.tgz -C ~/

	sed -i 's/\[\[/\[/g;s/\]\]/\]/g;s/==/=/g' ~/EasyRSA-3.0.3/easyrsa
	mv ~/EasyRSA-3.0.3/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.3/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.3.tgz
	cd /etc/openvpn/easy-rsa/

	# Create the PKI, set up the CA, the DH params and the Server + Client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn

	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem

	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key

	# Generate server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	case $DNS in
		1)
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;

		2)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem
plugin /usr/lib/openvpn/openvpn-auth-pam.so login
client-cert-not-required
username-as-common-name" >> /etc/openvpn/server.conf

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf

	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi

	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward

	if pgrep firewalld; then
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24

		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP

	else

		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo "#!/bin/sh -e
exit 0" > $RCLOCAL
		fi
		chmod +x $RCLOCAL

		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL

		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi

	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi

	service openvpn restart

	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "ตรวจพบเบื้องหลังเซิฟเวอร์ของคุณเป็น Network Addrsss Translation (NAT)"
		echo "NAT คืออะไร ? : http://www.greatinfonet.co.th/15396685/nat"
		echo ""
		echo "หากเซิฟเวอร์ของคุณเป็น (NAT) คุณจำเป็นต้องระบุ IP ภายนอกของคุณ"
		echo "หากไม่ใช่ กรุณาเว้นว่างไว้"
		echo "หรือหากไม่แน่ใจ กรุณาเปิดดูลิ้งค์ด้านบนเพื่อศึกษาข้อมูลเกี่ยวกับ (NAT)"
		echo ""
		read -p "External IP: " -e USEREXTERNALIP

		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi

	# Set Client
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP:$PORT@static.tlcdn1.com/cdn.line-apps.com/line.naver.jp/nelo2-col.linecorp.com/mdm01.cpall.co.th/lvs.truehits.in.th/dl-obs.official.line.naver.jp $PORT
http-proxy $IP $PROXY
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3
verb 3
auth-user-pass
" > /etc/openvpn/client-common.txt

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
http_port $PROXY
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname $HOSTNAME
END
sed -i $IP2 /etc/squid3/squid.conf;
service squid3 restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install OpenVPN and Squid Proxy Finish"
echo "IP Server : $IP"
echo "Protocal : $PROTOCAL"
echo "Port : $PORT"
echo "Hostname Proxy : $HOSTNAME"
echo "Proxy : $IP"
echo "Port : $PROXY"
echo "====================================================="
echo "ติดตั้งสำเร็จ... กรุณาพิมพ์คำสั่ง menu เพื่อไปยังขั้นตอนถัดไป"
echo "====================================================="

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
http_port $PROXY
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname $HOSTNAME
END
sed -i $IP2 /etc/squid/squid.conf;
service squid restart

echo ""
echo "Source by Mnm Ami"
echo "Donate via TrueMoney Wallet : 082-038-2600"
echo ""
echo "Install OpenVPN and Squid Proxy Finish"
echo "IP Server : $IP"
echo "Protocal : $PROTOCAL"
echo "Port : $PORT"
echo "Hostname Proxy : $HOSTNAME"
echo "Proxy : $IP"
echo "Port : $PROXY"
echo "====================================================="
echo "ติดตั้งสำเร็จ... กรุณาพิมพ์คำสั่ง menu เพื่อไปยังขั้นตอนถัดไป"
echo "====================================================="

	fi

	cd
	newclient "$CLIENT"

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
read -p "Password baru: " -e -i THIRD DatabasePass
echo ""
echo "Terakhir, sebutkan Nama Database untuk OCS Panels"
echo "Sila gunakan satu kata saja, tiada karakter khusus selain Underscore (_)"
read -p "Nama Database: " -e -i OCSREBORN DatabaseName
echo ""
echo "Okey, OCS Panel anda bersedia untuk di Install"
read -n1 -r -p "Tekan sebarang keyword untuk memulakan..."

#apt-get update
apt-get update && apt-get -y install mysql-server
mysql_secure_installation

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

chown -R mysql:mysql /var/lib/mysql/ && chmod -R 755 /var/lib/mysql/
#chmod -R 755 /var/lib/mysql/

apt-get install -y nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt

rm /etc/nginx/sites-enabled/default && rm /etc/nginx/sites-available/default
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
mv /etc/nginx/conf.d/vps.conf /etc/nginx/conf.d/vps.conf.backup
wget -O /etc/nginx/nginx.conf "https://adlottomm.000webhostapp.com/nginx.conf"
wget -O /etc/nginx/conf.d/vps.conf "https://adlottomm.000webhostapp.com/vps.conf"
sed -i 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php5/fpm/php.ini
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf

useradd -m vps && mkdir -p /home/vps/public_html
rm /home/vps/public_html/index.html && echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html && chmod -R g+rw /home/vps/public_html
service php5-fpm restart && service nginx restart


mysql -u root -p

CREATE DATABASE IF NOT EXISTS OCSREBORN;EXIT;
DROP DATABASE OCSREBORN;

cd /home/vps/public_html
apt-get -y install git
cd /home/vps/public_html
git init
git remote add origin https://github.com/rzengineer/Ocs-Panel-Reborns.git
git pull origin master
chmod 777 /home/vps/public_html/application/config/database.php


#mysql -u root -p
so2=$(expect -c "
spawn mysql -u root -p; sleep 3
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;EXIT;\r\"
expect eof; ")
echo "$so2"
#pass
#CREATE DATABASE IF NOT EXISTS OCS_PANEL;EXIT;


clear
echo "Buka Browser, akses alamat http://$MYIP:81/ dan lengkapi data2 seperti dibawah ini!"
echo "Database:"
echo "- Database Host: localhost"
echo "- Database Name: $DatabaseName"
echo "- Database User: root"
echo "- Database Pass: $DatabasePass"
echo ""
echo "Admin Login:"
echo "- Username: sesuai keinginan"
echo "- Password Baru: sesuai keinginan"
echo "- Masukkan Ulang Password Baru: sesuai keinginan"
echo ""
echo "Klik Install dan tunggu proses selesai, kembali lagi ke terminal dan kemudian tekan [ENTER]!"
sleep 3
echo ""
read -p "Jika Step diatas sudah dilakukan, sila tekan [Enter] untuk melanjutkan..."
echo ""
read -p "Jika anda benar-benar yakin Step diatas sudah dilakukan, sila tekan [Enter] untuk melanjutkan..."
echo ""

#mysql -u root -p
so2=$(expect -c "
spawn mysql -u root -p; sleep 3
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;EXIT;\r\"
expect eof; ")
echo "$so2"
#pass
#CREATE DATABASE IF NOT EXISTS OCS_PANEL;EXIT;

chmod 777 /home/fns/public_html/config
chmod 777 /home/fns/public_html/config/inc.php
chmod 777 /home/fns/public_html/config/route.php


clear
echo "Buka Browser, akses alamat http://$MYIP:81/ dan lengkapi data2 seperti dibawah ini!"
echo "Database:"
echo "- Database Host: localhost"
echo "- Database Name: $DatabaseName"
echo "- Database User: root"
echo "- Database Pass: $DatabasePass"
echo ""
echo "Admin Login:"
echo "- Username: sesuai keinginan"
echo "- Password Baru: sesuai keinginan"
echo "- Masukkan Ulang Password Baru: sesuai keinginan"
echo ""
echo "Klik Install dan tunggu proses selesai, kembali lagi ke terminal dan kemudian tekan tombol [ENTER]!"

sleep 3
echo ""
read -p "Jika Step diatas sudah dilakukan, silahkan Tekan tombol [Enter] untuk melanjutkan..."
echo ""
read -p "Jika anda benar-benar yakin Step diatas sudah dilakukan, silahkan Tekan tombol [Enter] untuk melanjutkan..."
echo ""
cd /root
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart

rm -f /root/jcameron-key.asc

apt-get -y --force-yes -f install libxml-parser-perl


rm -R /home/fns/public_html/installation

cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

chmod 755 /home/fns/public_html/config
chmod 644 /home/fns/public_html/config/inc.php
chmod 644 /home/fns/public_html/config/route.php

# info
clear
echo "=======================================================" | tee -a log-install.txt
echo "Silahkan login Panel Reseller di http://$MYIP:81" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Auto Script Installer OCS Panels | fawzya.net"  | tee -a log-install.txt
echo "             (http://www.overses.net/ - 085799054816)           "  | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Thanks " | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "Log Instalasi --> /root/log-install.txt" | tee -a log-install.txt
echo "=======================================================" | tee -a log-install.txt
cd ~/

	
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
