#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify

context.log_level = 'error'
magic_number = b"cIMG"
width = 25
height = 11
version = 1

payload = magic_number
payload += version.to_bytes(8,"little")
payload += struct.pack("<B",width) # I for 4 byte
payload += struct.pack("<H",height) # I for 4 byte
payload += b"A"*(width*height)

with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
