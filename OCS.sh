
# อัพเดตและติดตั้ง Mysql
apt-get update && apt-get -y install mysql-server

# ติดตั้งความปลอดภัยของ Mysql
mysql_secure_installation
# เมื่อใส่คำสั่งติดตั้งความปลอดภัยมันจะถามหารหัส Mysql ที่เราตั้งไว้
# และจะถามคำถามตาม 5 บรรทัดด้านล่างนี้ก็ให้ตอบตามนี้
Change the root password? [Y/n] n
Remove anonymous users? [Y/n] y
Disallow root login remotely? [Y/n] y
Remove test database and access to it? [Y/n] y
Reload privilege tables now? [Y/n] y

# เปลี่ยนเจ้าของไฟล์และเปลี่ยนสิทธิ์ในการเข้าถึง
chown -R mysql:mysql /var/lib/mysql/ && chmod -R 755 /var/lib/mysql/

# อัพเดตและติดตั้งสิ่งที่สำคัญ
apt-get -y install nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt

# ลบไฟล์, ย้ายไฟล์, ติดตั้ง Repo, เปลี่ยนเจ้าของไฟล์, เพิ่มผู้ใช้, สร้างโฟลเดอร์, รีเซตระบบเว็บไซต์
# คัดลอกบรรทัดที่ 23 ถึง 93 ทั้งหมดไปวางในเทอมินอลทีเดียว
rm /etc/nginx/sites-enabled/default && rm /etc/nginx/sites-available/default
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
mv /etc/nginx/conf.d/vps.conf /etc/nginx/conf.d/vps.conf.backup
cat > /etc/nginx/nginx.conf <<END
user www-data;

worker_processes 1;
pid /var/run/nginx.pid;

events {
        multi_accept on;
  worker_connections 1024;
}

http {
        gzip on;
        gzip_vary on;
        gzip_comp_level 5;
        gzip_types    text/plain application/x-javascript text/xml text/css;

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

cat > /etc/nginx/conf.d/vps.conf <<END
server {
  listen       81;
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
sed -i 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php5/fpm/php.ini
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
useradd -m vps && mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html && chmod -R g+rw /home/vps/public_html
service php5-fpm restart && service nginx restart

# สร้างฐานข้อมูลที่ไม่เคยมีอยู่
mysql -u root -p
# เมื่อพิมคำสั่งด้านบนแล้วจะถามหารหัส Mysql ที่เราตั้งไว้แล้วเอนเตอร์
# จากนั้นให้ใส่คำสั่งด้านล่างนี้
CREATE DATABASE IF NOT EXISTS OCSREBORN;EXIT;

# ติดตั้ง OCS จาก Github ของใครก็ไม่รู้
apt-get -y install git
cd /home/vps/public_html
git init
git remote add origin https://github.com/rzengineer/Ocs-Panel-Reborns.git
git pull origin master
chmod 777 /home/vps/public_html/application/config/database.php

# แก้ไขไฟล์
nano /home/vps/public_html/application/config/database.php
# เมื่อพิมคำสั่งด้านบนแล้วให้เลื่อนหา 3 บรรทัดล่างนี้เพื่อทำการแก้ไขตามนี้
$db['default']['username'] = "root";
$db['default']['password'] = "รหัสผ่าน VPS ของเรา";
$db['default']['database'] = "OCSREBORN";
# เมื่อเปลี่ยนแปลงเสร็จแล้วให้ทำการบันทึกโดยกด CTRL+X ตามด้วย Y และ Enter

# แก้ไขไฟล์
nano /home/vps/public_html/application/config/config.php
# เมื่อพิมคำสั่งด้านบนแล้วให้เลื่อนบรรทัดที่มีคำว่า config[‘base_url’] = $root;
# แล้วทำการแก้ไขตามด้านล่างนี้ เช่น $config[‘base_url’] = “http://192.168.33.29:81”;
$config[‘base_url’] = “http://ip:81”;
# เมื่อเปลี่ยนแปลงเสร็จแล้วให้ทำการบันทึกโดยกด CTRL+X ตามด้วย Y และ Enter

# เปิดเบราเซอร์และคัดลอกลิ้งค์ด้านล่างนี้ไปวางไว้ จากนั้นจะปรากฏหน้าต่างสร้างผู้ใช้ที่เป็นเจ้าของ OCS นี้
# ตรงคำว่า ip ให้เปลี่ยนเป็น IP ของเซิฟเวอร์เรา
http://ip:81/install

# เมื่อสร้างผู้ใช้สำเร็จก็ให้พิมคำสั่งนี้เพื่อลบไฟล์ติดตั้งออก
rm -rf /home/vps/public_html/install

# เข้า OCS โดยเปิดเบราเซอร์แล้วใส่ตามด้านล่างนี้
http://ip:81

# จบ
