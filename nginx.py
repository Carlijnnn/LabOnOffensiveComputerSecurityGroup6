import os
import logging as log

# setconfigfile("estctwist.nl", "/etc/nginx/sites-enabled/default.conf")
def setnginxconfig(website, path):
    f = open(path, "w")
    f.write(f"""
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    server_name _;
    location / {{
        proxy_pass https://{website};
    }}
}}
""")
    f.close()
    os.system("sudo service nginx restart")
