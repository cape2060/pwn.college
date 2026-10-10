#!/usr/bin/python3

import socket


sockets = []

for _ in range(1000):
    s = socket.socket()
    s.connect(("10.0.0.2",31337))
    sockets.append(s)
