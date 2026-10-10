#!/usr/bin/python3

import struct
from pwn import *
import os
import sys
"""pwn.college{MLikmxfLqMc85T0NCUuFhT31adj.0VOxMDMxwSM4ETN3EzW}"""
context.log_level = 'error'

with open("/challenge/flag.cimg","rb") as file:
    data = file.read()

pixel = []
content = data[12:]
for i in range(int.from_bytes(data[8:12],"little")):
    co = content[:10] 
    pixel.append((int.from_bytes(co[2:3],"little"),int.from_bytes(co[3:4],"little"),co[9:10]))
    content = content[10:]
max_y = max(p[1] for p in pixel)

header = data[:12].replace(b"\x01",max_y.to_bytes(1,"little"))
no_dir = int.from_bytes(data[8:12],"little")
content = data[12:]
replaced_content = b""


for d in range(no_dir):
    nrc = content[:10].replace(b"\x02\x00",b"\xea\xb9")
    replaced_content += nrc
    content = content[10:]

with open("new.cimg","wb") as file:
    file.write(header+replaced_content)
