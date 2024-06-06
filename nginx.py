import os
import logging as log

# setconfigfile("estctwist.nl", "/etc/nginx/sites-enabled/default.conf")
def setconfigfile(website, path):
    f = open(path, "w")
    f.write("""
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    server_name _;
    location / {
        try_files $uri $uri/ =404;
        proxy_pass https://{hostname}
    }
}
""".format(hostname = website))
    f.close()
    os.system("sudo service nginx restart")