# pip install scapy requests ipaddr pysqlite3

from scapy.all import *
import requests
import time, os, stat
import datetime
import optparse
import json
import ipaddr
import sqlite3
import threading

class torIpPool(threading.Thread):
    def __init__(self,torFileName,maxAge,torUrl):
        self.ipListValid=False
        self.exitThread=False
        self.torFileName=torFileName
        self.ipAge=0
        self.maxAge=maxAge
        self.ipV4list=[]
        self.ipV6list=[]
        self.torUrl=torUrl
        threading.Thread.__init__(self)

    def closeEvent(self):
        print('Close torIpPool')

    def run(self):
        print('start loop')
        while not self.exitThread:
            self.checkTorFile()
            self.loadFile()
            time.sleep(self.maxAge+1)

    def downloadIpList(self):
        print("Download TOR IP List...")
        print(self.torFileName)
        r = requests.get(self.torUrl, allow_redirects=True)
        f=open(self.torFileName, 'wb').write(r.content)        
       
        
    def checkTorFile(self):
        if os.path.isfile(self.torFileName):
            print("TOR-IP-File age in seconds: " + str(int(self.file_age_in_seconds())))
            if self.file_age_in_seconds() > self.maxAge:
                print("TOR-IP-File is older than "+str(self.maxAge)+' Seconds')
                self.downloadIpList()
            else:
                print("TOR-IP-File is up to date.")
        else:
            print("TOR-IP-File doesn't exist.")
            self.downloadIpList()
        
    def file_age_in_seconds(self):
        return time.time() - os.stat(self.torFileName)[stat.ST_MTIME]

    def loadFile(self):
        print("Read TOR-IP-File")
        f=open(self.torFileName, 'r')
        with open(self.torFileName, "r") as read_file:
            data = json.load(read_file)
        relayData=data['relays']
        self.ipListValid=False
        for ipPort in relayData:
            for ipPorts in ipPort['or_addresses']:
                ip=ipPorts.rsplit(':',1)[0]
                if ip[0]=='[':
                    ip6=ip.replace('[','').replace(']','')
                    self.ipV6list.append(ipaddr.IPv6Address(ip6).exploded)				
                else:
                    self.ipV4list.append(ip)
        f.close()
        self.ipListValid=True


class packet_sniffer(threading.Thread):
    def __init__(self,ethIf,ipv4List,ipv6List,pcapFile=''):
        self.ipv4List=ipv4List
        self.ipv6List=ipv6List
        self.ethIf=ethIf
        self.pcapFile=pcapFile
        threading.Thread.__init__(self)
    
    def closeEvent(self):
        pass

    def run(self):
        if self.pcapFile=='':
            sniff(filter='tcp',iface=self.ethIf,prn=self.PacketHandler, store=0) 
        else:
            sniff(filter='tcp',offline=self.pcapFile, store=0, prn=self.PacketHandler)

    def PacketHandler(self,pkt):
        try:
            sys.stdout.flush()
            SYN = 0x02
            S = pkt['TCP'].flags
            if S & SYN:
                ip46 = IPv6 if IPv6 in pkt else IP
                if ip46 in pkt:
                    ip_src=pkt[ip46].src
                    ip_dst=pkt[ip46].dst
                    if IPv6 in pkt:
                        ip6=ipaddr.IPv6Address(ip_dst).exploded
                        if ip6 in self.ipv6List:
                            print("***************************************")
                            print('IPv6 TOR-Session-Detected:')
                            print(str(ip_src) + " -> " + str(ip_dst))
                            timeNow=datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                            print ("Time:",timeNow)
                            print()
                            sys.stdout.flush()

                        
                    else:
                        if str(ip_dst) in self.ipv4List:
                            print("***************************************")
                            print('IPv4 TOR-Session-Detected:')
                            print(str(ip_src) + " -> " + str(ip_dst))
                            timeNow=datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                            print ("Time:",timeNow)
                            print()
                            sys.stdout.flush()
        except:
            print('.')



parser = optparse.OptionParser()
parser.add_option('-i', '--interface', action="store", dest="interface", help="string", default="Ethernet 5")
parser.add_option('-f', '--file', action="store", dest="pcapfile", help="string", default="")
options, args = parser.parse_args()

print("***************************************")
print("* TOR-Sniffer V.3.0 by Reto Schaedler *")
print("* PLEASE DONATE   paypal.me/retoPay   *")
print("***************************************")

torIpList=torIpPool('TOR_IP_LIST.dat',3600,'https://onionoo.torproject.org/details?search=flag:Guard') # torFileName,maxAge,torUrl
torIpList.start()
while not torIpList.ipListValid:
    time.sleep(0.1)
    print('.',end='')

print('Start Sniffer')
packet_sniffer1=packet_sniffer(options.interface,torIpList.ipV4list,torIpList.ipV6list,pcapFile=options.pcapfile)
packet_sniffer1.start()
print('Sniffer Started.')
time.sleep(1)
while True:
    pass

