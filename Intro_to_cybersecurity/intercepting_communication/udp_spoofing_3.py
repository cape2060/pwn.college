#!/usr/bin/python3

import socket

conn = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

conn.bind(("0.0.0.0",31337))
conn.settimeout(1)
for i in range(1,65535):
    n = conn.sendto(b"FLAG:10.0.0.1:31337",("10.0.0.2",i))


data,addr = conn.recvfrom(1024)

print(data.decode())
print('send',n,i)
