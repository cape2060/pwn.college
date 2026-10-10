#!/usr/bin/python3


from pwn import *


context.log_level = 'error'

with open('image.cimg','wb') as file:
    file.write(b"[lMg")


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
