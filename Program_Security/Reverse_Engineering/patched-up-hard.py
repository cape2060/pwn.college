#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("/challenge/patched-up-hard")

io = process()

io.recvuntil(b"Offset (hex) to change: ")

io.sendline("0x1fd8")
io.sendline("0x74")

for _ in range(4):
    io.sendline(b"0")
    io.sendline("0")

io.sendline(b"this is correct")
io.interactive()
