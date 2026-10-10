#!/usr/bin/python3

import struct
from pwn import *
from binascii import unhexlify
import sys

context.log_level = 'error'

magic_number = b"cIMG"
width = 0x2
height = 0x2
version = 2
ascii = ["c","I","M","G"]
red = [109,104,132,72]
green = [231,230,194,115]
blue = [222,137,24,123]

#"\x1b[38;2;109;231;222mc\x1b[0m\x1b[38;2;104;230;137mI\x1b[0m\x1b[38;2;132;194;024mM\x1b[0m\x1b[38;2;072;115;123mG\x1b[0m\x00";

payload = magic_number
payload += version.to_bytes(2,"little")
payload += struct.pack("<B",width) # B for 1 byte
payload += struct.pack("<B",height) # B for 1 byte
for i in range(width*height):
    payload += struct.pack("<B",red[i])+struct.pack("<B",green[i])+struct.pack("<B",blue[i])+ascii[i].encode()


with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
