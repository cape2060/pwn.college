#!/usr/bin/python3

import struct
from pwn import *


context.log_level = 'error'

with open('image.cimg','wb') as file:
#    payload  = b"cm6e"+struct.pack("<Q",135)
    payload = b"cm6e"+int(135).to_bytes(8,"little")
    file.write(payload)


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
