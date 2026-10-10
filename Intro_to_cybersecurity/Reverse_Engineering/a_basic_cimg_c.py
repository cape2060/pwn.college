#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify

context.log_level = 'error'
magic_number = b"cIMG"
width = 59
height = 24
version = 2

payload = magic_number
payload += version.to_bytes(4,"little")
payload += struct.pack("<H",width) # I for 4 byte
payload += struct.pack("<I",height) # I for 4 byte
for _ in range(width*height):
    payload += b"\x8c\x1d\x40\x41"



with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
