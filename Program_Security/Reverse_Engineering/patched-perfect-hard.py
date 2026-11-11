#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("/challenge/patch-perfect-hard")

io = process()

io.recvuntil(b"Offset (hex) to change: ")

# this patch the 32 bit relative jne to te
io.sendline(b"0x1f92")
io.sendline(b"0x84")

# this patch 8 bit instruction jne to je
io.sendline(b"0x2070")
io.sendline(b"0x74")

io.sendline(b"this is correct")
io.interactive()
