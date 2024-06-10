import os
import logging as log

# setconfigfile("estctwist.nl")
def setnginxconfig(website):
    f = open(f"/etc/nginx/sites-available/{website}.conf", "w")
    f.write(f"""
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name {website};
    location / {{
        proxy_pass https://{website};
    }}
}}

# Redirect HTTPS to HTTP
server {{
        listen 443 default_server;
        listen [::]:443 default_server;
        server_name _;

        location / {{
                return 301 http://$host$request_uri;
        }}
}}
""")
    f.close()
    os.system(f"sudo ln /etc/nginx/sites-available/{website}.conf /etc/nginx/sites-enabled/{website}.conf")
    os.system("sudo service nginx restart")
