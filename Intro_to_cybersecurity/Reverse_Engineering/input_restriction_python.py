#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify

context.log_level = 'error'
magic_number = b"cIMG"
width = 62
height = 23
version = 1

payload = magic_number
payload += version.to_bytes(2,"little")
payload += struct.pack("<I",width) # I for 4 byte
payload += struct.pack("<B",height) # I for 4 byte
payload += b"A"*(width*height)

with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
