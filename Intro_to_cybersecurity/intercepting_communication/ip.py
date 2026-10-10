#!/usr/bin/python3

from scapy.all import *

packet =IP(proto=0xFF,dst="10.0.0.2")/TCP()/Raw(b'hello')

send(packet)
