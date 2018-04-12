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
echo "==============================================="
echo -e "${cyan}╲╲╲╲╲┏━┳━━━━━━━━┓╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃◯┃╭┻┻╮╭┻┻╮┃╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃╮┃┃╭╮┃┃╭╮┃┃╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃╯┃┗┻┻┛┗┻┻┻┻╮╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃◯┃╭╮╰╯┏━━━┳╯╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃╭┃╰┏┳┳┳┳┓◯┃╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲╲┃╰┃◯╰┗┛┗┛╯╭┃╲╲╲ ${NC}"
echo -e "${cyan}╲╲╲╲.   ┻━━━━━━━━━━┻╲╲╲${NC}"
echo -e "${cyan}╲█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█ ${NC}"
echo -e "${cyan}╲█░╦─╦╔╗╦─╔╗╔╗╔╦╗╔╗░█ ${NC}"
echo -e "${cyan}╲█░║║║╠─║─║─║║║║║╠─░█ ${NC}"
echo -e "${cyan}╲█░╚╩╝╚╝╚╝╚╝╚╝╩─╩╚╝░█ ${NC}"
echo -e "${cyan}╲█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█ ${NC}"
echo "==============================================="
echo  -e "${yellow}Debian 8-9 Ubuntu 14.04-16.04 Support ${NC}"
echo  -e "${yellow}เมนูสคริป SCRIPT ${color1}By THIRDZ เวอร์ชั่นทดสอบ${NC}"
echo ""
echo -e "|${RED}1|${blue} OPENVPN (TERMINAL CONTROL) ${RED}✔   ${NC}
echo -e "${RED}ฟังก์ชั่นที่ 1 และ 2 เลือกอยางใดอย่างหนึ่งเท่านั้น ${NC}"
echo -e "|${RED}2|${blue} OPENVPN (PRITUNL CONTROL) ${GREEN}✔   ${NC}"
echo -e "|${RED}3|${blue} WEB OPENVPN ${yellow}✖   ${NC}"
echo -e "|${RED}4|${blue} WEB PANEL ${blue}✔   ${NC}"
echo -e "|${RED}5|${blue} VNSTAT (CHECK BANDWIDTH or DATA) ${cyan}✖   ${NC}"
echo -e "|${RED}6|${blue} SQUID PROXY ${magenta}✔   ${NC}"
echo ""
read -p "กรุณาเลือกฟังก์ชั่นที่ต้องการติดตั้ง (ตัวเลข) : " Menu

case $Menu in

	1)

#newclient () {
	newclient () {
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

IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
	IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	echo ""
	read -p "Do you really want to remove OpenVPN  (Y or N): " -e -i N REMOVE

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
		rm -f /usr/local/bin/menu
		echo ""
		echo "OpenVPN removed."
	else
		echo ""
		echo "Removal aborted."
	fi
	exit
else
	clear
	read -p "IP address : " -e -i $IP IP
	read -p "Port : " -e -i 1194 PORT
	echo ""
	echo -e " |${RED}1${NC}| UDP"
	echo -e " |${RED}2${NC}| TCP"
	echo ""
	read -p "Protocol : " -e -i 2 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo ""
	echo -e " |${RED}1${NC}| DNS Current system"
	echo -e " |${RED}2${NC}| DNS Google"
	echo ""
	read -p "DNS : " -e -i 1 DNS
	read -p "Port proxy : " -e -i 8080 PROXY
	echo ""
	echo -e " |${RED}1${NC}| 1 ไฟล์เชื่อมต่อได้ 1 เครื่องเท่านั้น สามารถสร้างไฟล์เพิ่มได้"
	echo -e " |${RED}2${NC}| 1 ไฟล์เชื่อมต่อได้หลายเครื่อง แต่ต้องสร้างบัญชีเพื่อใช้เชื่อมต่อ"
	echo -e " |${RED}3${NC}| 1 ไฟล์เชื่อมต่อได้ไม่จำกัดเครื่อง"
	echo ""
	read -p "OpenVPN system : " -e OPENVPNSYSTEM
	read -p "Client name: " -e CLIENT
	echo ""
	read -n1 -r -p "กด Enter 1 ครั้งเพื่อเริ่มทำการติดตั้ง หรือกด CTRL+C เพื่อยกเลิก"

	apt-get update
	apt-get install openvpn iptables openssl ca-certificates -y

	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	wget -O ~/EasyRSA-3.0.4.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz"
	tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.4.tgz
	cd /etc/openvpn/easy-rsa/
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	openvpn --genkey --secret /etc/openvpn/ta.key

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
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
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
crl-verify crl.pem" >> /etc/openvpn/server.conf
	case $OPENVPNSYSTEM in
		1)
		echo "client-to-client" >> /etc/openvpn/server.conf
		;;
		2)
		echo "plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/login" >> /etc/openvpn/server.conf
		echo "client-cert-not-required" >> /etc/openvpn/server.conf
		echo "username-as-common-name" >> /etc/openvpn/server.conf
		;;
		3)
		echo "duplicate-cn" >> /etc/openvpn/server.conf
		;;
	esac

	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi

	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL

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
verb 3" > /etc/openvpn/client-common.txt

	case $OPENVPNSYSTEM in
		2)
		echo "auth-user-pass" >> /etc/openvpn/client-common.txt
		;;
	esac

	cd
	apt-get -y install nginx
	cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes 2;
pid /var/run/nginx.pid;
events {
	multi_accept on;
        worker_connections 1024;
}
http {
	autoindex on;
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        server_tokens off;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;
	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;
	fastcgi_read_timeout 600;
        include /etc/nginx/conf.d/*.conf;
}
END
	mkdir -p /home/vps/public_html
	echo "<pre>Source by BaNk PrP | Donate via TrueMoney Wallet : 082-0083374</pre>" > /home/vps/public_html/index.html
	echo "<?phpinfo(); ?>" > /home/vps/public_html/info.php
	args='$args'
	uri='$uri'
	document_root='$document_root'
	fastcgi_script_name='$fastcgi_script_name'
	cat > /etc/nginx/conf.d/vps.conf <<END
server {
    listen       85;
    server_name  127.0.0.1 localhost;
    access_log /var/log/nginx/vps-access.log;
    error_log /var/log/nginx/vps-error.log error;
    root   /home/vps/public_html;
    location / {
        index  index.html index.htm index.php;
	try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        include /etc/nginx/fastcgi_params;
        fastcgi_pass  127.0.0.1:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
END

	if [[ "$VERSION_ID" = 'VERSION_ID="7"' || "$VERSION_ID" = 'VERSION_ID="8"' || "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
		if [[ -e /etc/squid3/squid.conf ]]; then
			apt-get -y remove --purge squid3
		fi

		apt-get -y install squid3
		cat > /etc/squid3/squid.conf <<END
http_port $PROXY
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
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
http_access allow localnet
http_access allow localhost
http_access deny all
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
END
		IP2="s/xxxxxxxxx/$IP/g";
		sed -i $IP2 /etc/squid3/squid.conf;
		if [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
			service squid3 restart
			/etc/init.d/openvpn restart
			/etc/init.d/nginx restart
		else
			/etc/init.d/squid3 restart
			/etc/init.d/openvpn restart
			/etc/init.d/nginx restart
		fi

	elif [[ "$VERSION_ID" = 'VERSION_ID="9"' || "$VERSION_ID" = 'VERSION_ID="16.04"' || "$VERSION_ID" = 'VERSION_ID="17.04"' ]]; then
		if [[ -e /etc/squid/squid.conf ]]; then
			apt-get -y remove --purge squid
		fi

		apt-get -y install squid
		cat > /etc/squid/squid.conf <<END
http_port $PROXY
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
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
http_access allow localnet
http_access allow localhost
http_access deny all
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
END
		IP2="s/xxxxxxxxx/$IP/g";
		sed -i $IP2 /etc/squid/squid.conf;
		/etc/init.d/squid restart
		/etc/init.d/openvpn restart
		/etc/init.d/nginx restart
	fi

fi

	wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/banklovelo01/nonstop/master/menu"
	chmod +x /usr/local/bin/menu
	apt-get -y install vnstat
	cd /etc/openvpn/easy-rsa/
	./easyrsa build-client-full $CLIENT nopass
	newclient "$CLIENT"
	cp /root/$CLIENT.ovpn /home/vps/public_html/
	rm -f /root/$CLIENT.ovpn
	useradd -e `date -d "365 days" +"%Y-%m-%d"` -s /bin/false -M $CLIENT
	EXP="$(chage -l $CLIENT | grep "Account expires" | awk -F": " '{print $2}')"
	echo -e "$CLIENT\n$CLIENT\n"|passwd $CLIENT &> /dev/null
	echo ""
	echo "Source by BaNk PrP"
	echo "Donate via TrueMoney Wallet : 082-0083374"
	echo ""
	echo "OpenVPN, Squid Proxy, Nginx .....Install finish."
	echo "IP server : $IP"
	echo "Port : $PORT"
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "Protocal : UDP"
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "Protocal : TCP"
	fi
	echo "Port nginx : 85"
	echo "Proxy : $IP"
	echo "Port proxy : $PROXY"
	echo "Download config (only you) : http://$IP:85/$CLIENT.ovpn"
	echo ""
	echo "====================================================="
	echo "ติดตั้งสำเร็จ... กรุณาพิมพ์คำสั่ง menu เพื่อไปยังขั้นตอนถัดไป"
	echo "====================================================="
	echo ""
	exit
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
	#echo "3 กรุณารอสักนิด ขณะนี้ยังไม่ได้ติดตั้งคำสั่งนี้"
	if
    sudo apt-get install opvpn
	
	sudo openvpn --config client.ovpn
    
    sudo apt-get install network-manager-openvpn
# Debian 8
	if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
	sudo wget http://swupdate.openvpn.org/as/openvpn-as-2.5-Debian8.amd_64.deb 
   
    dpkg -i openvpn-as-2.5-Debian8.amd_64.deb
    
    sudo passwd openvpn
    echo"ตั้งรหัสผ่านของท่าน"
    
    # Ubuntu 16.04
	elif [[ "$VERSION_ID" = 'VERSION_ID="16.04"' ]]; then
	wget http://swupdate.openvpn.org/as/openvpn-as-2.0.10-Ubuntu14.amd_64.deb

    dpkg -i openvpn-as-2.0.10-Ubuntu14.amd_64.deb

    sudo passwd openvpn
    echo"ตั้งรหัสผ่านของท่าน"
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
nano /home/vps/public_html/application/config/config.php

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
	#echo "5 กรุณารอสักนิด ขณะนี้ยังไม่ได้ติดตั้งคำสั่งนี้"
	
   wget http://swupdate.openvpn.org/as/openvpn-as-2.0.10-Ubuntu14.amd_64.deb
   
   dpkg -i openvpn-as-2.0.10-Ubuntu14.amd_64.deb

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
