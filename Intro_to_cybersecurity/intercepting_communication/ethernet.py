#!/usr/bin/python3

from scapy.all import *

packet = Ether(type=0xFFFF)/IP(dst="10.0.0.2")/TCP()/Raw('hello')

sendp(packet,iface='eth0')
