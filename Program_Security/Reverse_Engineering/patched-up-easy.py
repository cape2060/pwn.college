#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("/challenge/patched-up-easy")

io = process()

io.recvuntil(b"Offset (hex) to change: ")

# this patch the jne instruction to je instruction so the 
# check become like if the license is not equal then call win
io.sendline("0x28e3")
io.sendline("0x74")

for _ in range(4):
    io.sendline(b"0")
    io.sendline("0")

io.sendline(b"this is correct")
io.interactive()
