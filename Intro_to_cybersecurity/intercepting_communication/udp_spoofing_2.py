#!/usr/bin/python3

import socket

conn = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

conn.bind(("0.0.0.0",31337))


n = conn.sendto(b"FLAG:10.0.0.1:31337",("10.0.0.2",31338))


data,addr = conn.recvfrom(1024)

print(data.decode())
print('send',n)
