#!/usr/bin/python3

import struct
from pwn import *


context.log_level = 'error'
width = 59
height = 21
version = 1

payload = b"CmgE"
payload += version.to_bytes(8,"little")
payload += struct.pack("<I",width) # I for 4 byte
payload += struct.pack("<I",height) # I for 4 byte
payload += b"A"*(width*height)

with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
