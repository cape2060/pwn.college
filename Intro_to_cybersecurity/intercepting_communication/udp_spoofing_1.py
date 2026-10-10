#!/usr/bin/python3

import socket

conn = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

conn.bind(("0.0.0.0",31337))


conn.sendto(b"FLAG",("10.0.0.2",31338))

print('Packet Send')
