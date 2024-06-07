import os
import logging as log

# setconfigfile("estctwist.nl", "/etc/nginx/sites-enabled/default.conf")
def setconfigfile(website, path):
    f = open(path, "w")
    f.write(f"""
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    server_name _;
    location / {{
        try_files $uri $uri/ =404;
        proxy_pass https://{website};
    }}
}}
""")
    f.close()
    os.system("sudo service nginx restart")


setconfigfile("gewis.nl", "/etc/nginx/sites-enabled/default")