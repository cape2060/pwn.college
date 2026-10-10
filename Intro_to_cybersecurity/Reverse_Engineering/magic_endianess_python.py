#!/usr/bin/python3


from pwn import *


context.log_level = 'error'

with open('image.cimg','wb') as file:
    file.write(int("65674D43",16).to_bytes(4,'little'))


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
