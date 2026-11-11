#!/usr/bin/python3

from pwn import *
from Crypto.Util.number import long_to_bytes

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./know-the-yancode-hard")

# Your code here
io = process()

payload = long_to_bytes(0xb5bb9c6c)

io.send(payload)

io.interactive()
