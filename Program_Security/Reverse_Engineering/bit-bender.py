#!/usr/bin/python3

from pwn import *

enc_pas = "cUMZOyhRIcYRMant"

password = "".join([chr(((((ord(c) << 2) & 0xff) | ((ord(c) >> 6) & 0xff)) - 0x1f) & 0xff) for c in enc_pas])

io = process("./bit-bender")

io.sendline(password.encode('latin-1'))

io.interactive()
