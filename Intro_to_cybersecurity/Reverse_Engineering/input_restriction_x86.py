#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify

context.log_level = 'error'
magic_number = unhexlify("63494d47")
width = 0x40
height = 0xc
version = 1

payload = magic_number
payload += version.to_bytes(2,"little")
payload += struct.pack("<Q",width) # I for 4 byte
payload += struct.pack("<H",height) # I for 4 byte
payload += b"A"*(width*height)

with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
