#!/usr/bin/python3

from pwn import * 
context.log_level = 'error'

io = process(['nc','10.0.0.2','31337'])

io.interactive()
