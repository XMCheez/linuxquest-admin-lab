# Apache Setup for LinuxQuest

## Local Domain

Edit /etc/hosts and add:

127.0.0.1 linuxquest.local

## Enable Apache Modules

Run:

sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod auth_basic
sudo a2enmod authn_file
sudo systemctl restart apache2

## Virtual Host Configuration

File:

/etc/apache2/sites-available/LinuxQuest.conf

Example config:

<VirtualHost *:80>
    ServerName linuxquest.local
    ProxyPreserveHost On

    Alias /admin /var/www/html/admin

    <Directory /var/www/html/admin>
        AuthType Basic
        AuthName "Admin Area - Login Required"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>

    ProxyPass /admin !
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>

## Run Node App

node server.js

## Access

- http://linuxquest.local
- http://linuxquest.local/admin

