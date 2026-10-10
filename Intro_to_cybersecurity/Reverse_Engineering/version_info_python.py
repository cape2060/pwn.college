#!/usr/bin/python3

import struct
from pwn import *


context.log_level = 'error'

with open('image.cimg','wb') as file:
    payload  = b"(Nmg"+struct.pack("<Q",116)
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
