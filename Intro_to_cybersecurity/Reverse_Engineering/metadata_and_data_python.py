#!/usr/bin/python3

import struct
from pwn import *


context.log_level = 'error'
width = 46
height = 20
version = 1

payload = b"<NMg"
payload += version.to_bytes(4,"little")
payload += struct.pack("<Q",width) # Q for 8 byte
payload += struct.pack("<B",height) # C for 1 byte
payload += b"A"*(width*height)

with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
