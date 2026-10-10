#!/usr/bin/python3

import socket

conn = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

conn.bind(("0.0.0.0",31338))

conn.sendto(b"Hello, World!\n",("10.0.0.2",31337))


data,addr = conn.recvfrom(1024)

print(data.decode())
