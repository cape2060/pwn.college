#!/usr/bin/python3

from scapy.all import *

packet =IP(dst="10.0.0.2")/TCP(sport=31337,dport=31337,
seq=31337,
ack=31337,
flags="APRSF")/Raw(b"Get me flag")

send(packet)
