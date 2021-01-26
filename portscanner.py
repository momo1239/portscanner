import socket
import sys
from struct import *
import binascii
from scapy.all import *
from datetime import datetime

def tcpscan(host, port):
    time = datetime.now()
    what = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        what.connect((host, port))
        print("Port Open: " + str(port))
        what.close()
  
    except:
        print("Port Closed: " + str(port))
    time2 = datetime.now()
    total = time2 -time
    print("Port Scan Completed in: " + str(total))

def synscan():
    packet = sr1(IP(dst = "192.168.1.1") / TCP(dport = 80, flags="S"))
    packetflag = packet.getlayer(TCP).flags
    if packetflag == "SA":
        print("Open")
    else:
        print("Closed")
synscan()



class TCP:
    def __init__(self, srcip, destip, destport):
        # tcp segment
        self.srcport = 0x3039 
        self.destport = destport
        self.seqnum = 100
        self.acknum = 0x0
        self.dataoffset = 0x5
        #flags
        self.fin = 0
        self.syn = 1
        self.ack = 0
        self.rst = 0
        self.psh = 0
        self.urg = 0
        self.window = 0x7110
        self.checksum = 0x0
        self.urgpointer = 0
        self.reserved = 0
        self.offresflag = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5) + (self.dataoffset << 12) + (self.reserved << 9)

        #ip header
        self.ver = 4
        self.ihl = 5
        self.typeofser = 0
        self.total = 0
        self.id = 33981
        self.flag = 0
        self.fragoff = 0
        self.ttl = 64
        self.proto = socket.IPPROTO_TCP
        self.destip = destip
        self.srcip = srcip
        self.daddress = socket.inet_aton(destip)
        self.saddress = socket.inet_aton(srcip)
        self.verhihl = (self.ver << 4) + self.ihl
        self.flago = (self.flag << 13) + self.fragoff
        self.headerchecksum = 0

        self.tcpheader = b""
        self.ipheader = b""
        self.packet = b""
    

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1]
            s += w
            s = (s >> 16) + (s & 0xffff)
            s = ~s & 0xffff
            return s

    def buildtcpheader(self):
        tcphdr = pack("!HHLLHHHH", self.srcport, self.destport,
                        self.seqnum, self.acknum, self.offresflag,
                        self.window, self.checksum, self.urgpointer)
        return tcphdr
    
    def buildipheader(self):
        iphdr = pack("!BBHHHBBH4s4s", self.verhihl, self.typeofser,
                        self.total, self.id, self.flago, self.ttl,
                        self.proto, self.headerchecksum, self.saddress,
                        self.daddress)
        return iphdr
    
    def buildpacket(self):
        okiphdr = pack("!BBHHHBBH4s4s", self.verhihl, self.typeofser,
                        self.total, self.id, self.flago, self.ttl,
                        self.proto, self.calc_checksum(self.buildipheader()),
                        self.saddress, self.daddress)

        tcphdr = self.buildtcpheader()
        psh = pack("!4s4sBBH", self.saddress, self.daddress, self.checksum, self.proto, len(tcphdr))
        psh1 = psh + tcphdr
        oktcphdr = pack("!HHLLHHHH", self.srcport, self.destport,
                        self.seqnum, self.acknum, self.offresflag,
                        self.window, self.calc_checksum(psh1), self.urgpointer)
        
        self.ipheader = okiphdr
        self.tcpheader = oktcphdr
        self.packet = okiphdr + oktcphdr
    
    def sendpacket(self):
        what = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        what.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        wow = "172.18.219.23"
        what.bind((wow, 7878))
        what.sendto(self.packet, (self.destip, 0))
        data = what.recv(1010)
        what.close()
        return data
    
    def checkopen(port, response):
        cont = binascii.hexlify(response)
        if cont[65:68] == b"012":
            print("open")
        else:
            print("closed")


    

    
        
    

    

        
    

p = TCP("172.18.219.23", "192.168.1.1", 80)
p.buildpacket()
result = p.sendpacket()
checkopen(80, result)






        
