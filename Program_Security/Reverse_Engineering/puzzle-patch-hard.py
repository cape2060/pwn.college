#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("/challenge/puzzle-patch-hard")

io = process()

io.recvuntil(b"Offset (hex) to change: ")

io.sendline(b"0x1efc")
io.sendline(b"0x74")


io.sendline(b"this is correct")
io.interactive()
