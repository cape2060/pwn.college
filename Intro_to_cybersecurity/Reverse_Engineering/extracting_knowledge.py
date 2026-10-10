#!/usr/bin/python3

from pwn import *
import struct
import os
import sys

"""pwn.college{8VDm8zSicesspP3ddz5j6pG-K3F.0lMxMDMxwSM4ETN3EzW}"""

with open("new.cimg","rb") as file:
    data = file.read()

header = data[:12]
top = header[:6]
bottom = header[8:]
w = 100
h = 60
header = top + w.to_bytes(1,"little")+h.to_bytes(1,"little")+bottom


content = data[12:]
no_of_dir = int.from_bytes(data[8:12],"little")
x = 0
y = 0
def render(payload,x,y):
    payload = payload[:-2]
    payload += struct.pack("BB",x,y)
    return payload
actual = header
for i in range(no_of_dir):
    code = int.from_bytes(content[:1],"little")
    if code == 3:
        width = int.from_bytes(content[3:4],"little")
        height = int.from_bytes(content[4:5],"little")
        payload = content[:5+(width*height)]
        actual += payload
        content = content[5+(width*height):]
    elif code == 4:
        payload = render(content[:8],x,y)
        actual += payload
        content = content[8:]
        x += 10
        if x == 100:
            x = 0
            y+= 10


with open("n.cimg","wb") as i:
    i.write(actual)
