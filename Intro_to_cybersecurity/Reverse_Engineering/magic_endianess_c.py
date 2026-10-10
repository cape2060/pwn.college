#!/usr/bin/python3


from pwn import *


context.log_level = 'error'
a=1917734747
with open('image.cimg','wb') as file:
    file.write(a.to_bytes(4,'little'))


io = process(['/challenge/cimg','image.cimg'])

io.interactive()
