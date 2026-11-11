#!/usr/bin/python3

from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./know-the-yancode-easy")

# Your code here
io = process()

payload =  b"\xd2\x4e\xa8\x5b\xf8\xd5\x5a\x61"

io.send(payload)

io.interactive()
