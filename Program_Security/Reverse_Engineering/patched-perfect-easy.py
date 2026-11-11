#!/usr/bin/python3

from pwn import *

context.arch = "amd64"

context.log_level = "error"

elf = context.binary = ELF("/challenge/patch-perfect-easy")

io = process()

io.recvuntil(b"Offset (hex) to change: ")

io.sendline(b"0x1e6c")
io.sendline(b"0x74")

io.sendline(b"0x2103")
io.sendline(b"0x74")

io.sendline(b"this is correct")
io.interactive()
