#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify

context.log_level = 'error'
magic_number = b"cIMG"
width = 44
height = 21
version = 2

payload = magic_number
payload += version.to_bytes(2,"little")
payload += struct.pack("<Q",width) # I for 4 byte
payload += struct.pack("<H",height) # I for 4 byte
for _ in range(44*21):
    payload += b"\x8c\x1d\x40\x41"



with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
