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
red = [35,16,184,16]
green = [151,74,116,231]
blue = [93,65,152,151]

print("Get the desired output in pwndbg using command:\nx/s &desired_output")
#"\033[38;2;035;151;093mc\033[0m\033[38;2;016;074;065mI\033[0m\033[38;2;184;116;152mM\033[0m\033[38;2;016;231;151mG\033[0m"

payload = magic_number
payload += version.to_bytes(2,"little")
payload += struct.pack("<B",width) # I for 4 byte
payload += struct.pack("<B",height) # I for 4 byte

for i in range(width*height):
    payload += struct.pack("<B",red[i])+struct.pack("<B",green[i])+struct.pack("<B",blue[i])+ascii[i].encode()


with open('image.cimg','wb') as file:
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
