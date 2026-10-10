#!/usr/bin/python3

from scapy.all import *

syn = IP(dst="10.0.0.2")/TCP(sport=31337,
dport=31337,
flags="S",
seq=31337)

synack = sr1(syn,timeout=2)

ack = IP(dst="10.0.0.2")/TCP(sport=31337,dport=31337,flags="A",seq=synack.ack,ack=synack.seq+1)

send(ack)

print('TCP Handshake complete!!!')
